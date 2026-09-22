// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y279 — the `storage-backend-filesystem` atom (§5.24 storage): a
//! **durable, filesystem-backed** [`Volume`] / [`StorageBackend`], the wz
//! counterpart of zenoh's `zenoh-backend-filesystem` plugin. It plugs into the
//! same runtime-agnostic seam ([`wz_session_core::storage_backend`] /
//! [`wz_session_core::storage_volume`]) the in-memory
//! [`MemoryStorage`](wz_session_core::storage_backend::MemoryStorage) /
//! [`MemoryVolume`](wz_session_core::storage_volume::MemoryVolume) implement,
//! and lives in the std runtime crate because the `no_std` kernel has no
//! filesystem.
//!
//! ## Model: the directory IS the store (R2801)
//!
//! A value lives as a RAW FILE at its key's path under the storage's base
//! directory -- `demo/a/b` is the file `<base>/demo/a/b` holding exactly the
//! payload bytes -- and the two things a raw file cannot carry, the value's
//! encoding and the timestamp that versioned it, live in the `.zenoh_datainfo`
//! sidecar ([`crate::filesystem_datainfo`]). Every read goes to the directory:
//! [`get`](StorageBackend::get) opens the key's file, and
//! [`get_all_entries`](StorageBackend::get_all_entries) walks the tree. That is
//! upstream's backend, and it makes the directory a mirror of the key space in
//! BOTH directions: a file an operator drops into the tree is a value this
//! storage serves (encoding guessed from its extension, timestamp from its
//! modification time), and a value this storage holds is a file anyone can
//! read.
//!
//! This replaces the store R311y279 built, which kept a full in-memory copy of
//! every value and one opaque `k<hash>` record per key. That copy was not a
//! choice -- the seam's read handed out a BORROW, which only something the
//! backend owns can satisfy -- and R2800 removed the borrow. Two consequences of
//! the copy are gone with it: the store no longer holds its whole contents in
//! memory, and it no longer serves its directory as it stood when it opened.
//! The owner decided the shape at R2573 (mirror the user's directory tree, full
//! parity, rather than remain an opaque durable store).
//!
//! The key-to-path rules -- identity on unix, the conflict suffix when a key is
//! also a directory, the `@root` file for the mount-point key -- are
//! [`crate::filesystem_keypath`]'s, and each is upstream's.
//!
//! ## Durability, which is where wz is deliberately STRONGER
//!
//! Upstream creates the key's file in place and writes into it; its create
//! truncates first, so a crash mid-write loses the previous value, and nothing
//! in that repository fsyncs. wz writes the payload to a file in its staging
//! directory ([`STAGING_DIR`]), `fsync`s it, `rename`s it over the key's path,
//! and `fsync`s the directory that now names it -- so the key's path only ever
//! names a complete value, and a committed mutation survives a power loss. The
//! sidecar's rows are written with `sync` for the same reason. A directory this
//! store creates on the way to a key is `fsync`ed into its parent too.
//!
//! ## A write that fails (R311y831, restated for a store with no copy)
//!
//! [`StorageWriteError`](wz_session_core::storage_backend::StorageWriteError)
//! means the mutation is not committed, and nothing above may record it: the
//! newer-wins record, the replication log and the aligner digest all stay
//! silent (`StorageState::process_put` propagates instead of recording), which
//! is what upstream's storage service does on a failed `put`. What a READ shows
//! after a failure is now simply what the directory shows -- the seam's
//! "serve what a reopen would show" holds by construction, because every read
//! IS a reopen. The one partial state is ordered on purpose: the payload lands
//! before its row, so a failure or crash between the two leaves the new bytes
//! described by the PREVIOUS row. That timestamp is older than the truth, so an
//! aligning peer re-sends the value and the store converges; the opposite order
//! would leave old bytes under a new timestamp, which no peer would ever
//! correct.
//!
//! ## Concurrency
//!
//! One [`FilesystemStorage`] owns its directory, and that is now ENFORCED: the
//! sidecar is a RocksDB database, whose lock file refuses a second open of the
//! same directory while the first lives -- another wz store, or zenohd. A store
//! is single-threaded (`&mut self` serializes every mutation).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use wz_session_core::encoding::encoding_from_mime;
use wz_session_core::ntp64::Ntp64;
use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::storage_backend::{
    History, StorageBackend, StorageInsertionResult, StorageReadError, StorageWriteError,
    StorageWriteResult, StoredData,
};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_volume::{Capability, Persistence, Volume, VolumeError};

use crate::filesystem_datainfo::{self, DataInfo, DataInfoError, DataInfoStore, DB_FILENAME};
use crate::filesystem_keypath::{
    is_confinable, is_keyexpr, is_listable_key, relpath_to_zkey, trimmed_key, zkey_to_relpath,
    CONFLICT_SUFFIX, ROOT_KEY, STAGING_DIR,
};

/// Process-lifetime staging-file counter, so two writes in flight never share a
/// staging path (paired with the pid).
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The timestamp id upstream stamps a file that was not put through zenoh:
/// `TimestampId::try_from([1])`, whose significant bytes are the one `0x01`.
const FILE_TIME_ZID: [u8; 1] = [0x01];

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

/// The two storage properties that decide how a read treats the directory,
/// named and defaulted as upstream's fs volume names and defaults them
/// (`follow_links` false, `keep_mime_types` true).
///
/// They are here because the directory-tree layout is what gives them anything
/// to decide -- with the old hashed layout there was no link to follow and no
/// extension to read. Nothing maps a storage's configuration onto them yet: that
/// is the next round, together with `read_only`, `dir` and `on_closure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemOptions {
    /// Serve, list and write paths reached through a symbolic link inside the
    /// storage's directory. Off, a path with a link in it -- below the base
    /// directory; the base directory itself may be one -- is neither read,
    /// listed nor written.
    pub follow_links: bool,
    /// For a file that has no sidecar row, guess its encoding from its
    /// extension. Off, such a file is served as `application/octet-stream`.
    pub keep_mime_types: bool,
}

impl Default for FilesystemOptions {
    fn default() -> Self {
        Self {
            follow_links: false,
            keep_mime_types: true,
        }
    }
}

/// A durable, filesystem-backed [`StorageBackend`] whose directory tree mirrors
/// its key space (see the module note).
#[derive(Debug)]
pub struct FilesystemStorage {
    base_dir: PathBuf,
    data_info: DataInfoStore,
    options: FilesystemOptions,
    /// R2382 — force a directory `fsync` to fail while the `rename` it follows
    /// still lands: the one failure no filesystem fixture can arrange. R2801
    /// keeps it for the same claim in its new form -- the store refuses the
    /// write AND a read shows what the directory shows.
    #[cfg(test)]
    fail_dir_sync: bool,
    /// R2801 — force the unlink of a key's file to fail. The old fixture made a
    /// key's file a DIRECTORY, which the new layout reads as "this key is also a
    /// prefix" and routes to the conflict name instead, so a failed unlink is
    /// injected at the one call that performs it.
    #[cfg(test)]
    fail_unlink: bool,
}

impl FilesystemStorage {
    /// Open (creating if absent) the store rooted at `dir` with upstream's
    /// default [`FilesystemOptions`].
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        Self::open_with(dir, FilesystemOptions::default())
    }

    /// Open (creating if absent) the store rooted at `dir`.
    ///
    /// Nothing is read into memory: the directory is the store. Opening
    /// creates the directory, clears what a crash left in the staging area (no
    /// key's path ever named those bytes, so they are debris, not data), and
    /// opens the sidecar -- which fails while another store holds the same
    /// directory.
    pub fn open_with(dir: PathBuf, options: FilesystemOptions) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let staging = dir.join(STAGING_DIR);
        match fs::remove_dir_all(&staging) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot clear the staging area {}: {e}", staging.display()),
                ))
            }
        }
        let data_info = DataInfoStore::open(&dir).map_err(|e| {
            io::Error::other(format!(
                "cannot open the data-info sidecar of {}: {e}",
                dir.display()
            ))
        })?;
        Ok(Self {
            base_dir: dir,
            data_info,
            options,
            #[cfg(test)]
            fail_dir_sync: false,
            #[cfg(test)]
            fail_unlink: false,
        })
    }

    /// R2382 — a store whose directory `fsync` always fails. Test-only.
    #[cfg(test)]
    fn with_failing_dir_sync(mut self) -> Self {
        self.fail_dir_sync = true;
        self
    }

    /// R2801 — a store whose key-file unlink always fails. Test-only.
    #[cfg(test)]
    fn with_failing_unlink(mut self) -> Self {
        self.fail_unlink = true;
        self
    }

    /// The path a key's value is placed at, or `None` when the key may not be
    /// placed at all.
    ///
    /// `None` is the mount-point key and takes [`ROOT_KEY`]. A `Some` key must be
    /// a key expression ([`is_keyexpr`]) -- upstream only ever receives one, by
    /// type, and wz's seam hands a bare string, so this is where that guarantee
    /// is restored; without it a key containing the conflict suffix would be
    /// placed and then read back as a different key. It must be confinable
    /// ([`is_confinable`]) and must not name one of the store's own entries: the
    /// sidecar directory and the staging area are refused as a first chunk, and
    /// the exact key [`ROOT_KEY`] is refused because it would ALIAS the
    /// mount-point slot. ⚠ The last three are refusals upstream does not make --
    /// it writes a key under its data-info directory, and serves `@root` and the
    /// mount point as one value -- and each is in the safe direction: a store
    /// that answers a different key than it was asked, or writes into its own
    /// database, is worse than one that refuses.
    fn key_path(&self, key: Option<&str>) -> Option<PathBuf> {
        let zkey = match key {
            None => ROOT_KEY,
            Some(k) => {
                let first = k.split('/').next().unwrap_or(k);
                if !is_keyexpr(k)
                    || !is_confinable(k)
                    || k == ROOT_KEY
                    || first == DB_FILENAME
                    || first == STAGING_DIR
                {
                    return None;
                }
                k
            }
        };
        Some(self.base_dir.join(zkey_to_relpath(zkey).as_ref()))
    }

    /// Whether a path has a symbolic link in it at or below the base directory.
    /// The base directory itself is not minded -- where an operator put the
    /// store is not a link inside it. Upstream's `contains_symlink`.
    fn contains_symlink(&self, path: &Path) -> bool {
        if is_symlink(path) {
            return true;
        }
        let mut current = path;
        while let Some(parent) = current.parent() {
            if parent == self.base_dir {
                return false;
            }
            if is_symlink(parent) {
                return true;
            }
            current = parent;
        }
        false
    }

    /// Whether this store reads `file` at all: it is a regular file (through
    /// links) and, unless links are followed, reached through none.
    fn readable(&self, file: &Path) -> bool {
        file.is_file() && (self.options.follow_links || !self.contains_symlink(file))
    }

    /// Where the value placed at `target` is: `target` itself, or its
    /// conflict-suffixed name when `target` is a directory. Upstream's
    /// `read_file` order.
    fn locate(&self, target: &Path) -> Option<PathBuf> {
        if self.readable(target) {
            return Some(target.to_path_buf());
        }
        let conflict = conflict_path(target);
        self.readable(&conflict).then_some(conflict)
    }

    /// The encoding and timestamp of `file`: its sidecar row, or -- for a file
    /// not put through zenoh -- the extension guess and the modification time.
    fn metadata_of(&self, file: &Path) -> Result<DataInfo, ReadFailure> {
        if let Some(info) = self.data_info.get(file).map_err(ReadFailure::DataInfo)? {
            return Ok(info);
        }
        Ok(DataInfo {
            encoding: Some(self.guess_encoding(file)),
            timestamp: file_time_timestamp(file)?,
        })
    }

    /// Upstream's `guess_encoding`: the MIME type the extension names (the
    /// `mime_guess` table, octet-stream when it names none), parsed as zenoh
    /// parses an encoding string; octet-stream outright when
    /// [`keep_mime_types`](FilesystemOptions::keep_mime_types) is off.
    fn guess_encoding(&self, file: &Path) -> EncodingHint {
        if self.options.keep_mime_types {
            encoding_from_mime(
                mime_guess::from_path(file)
                    .first_or_octet_stream()
                    .essence_str(),
            )
        } else {
            EncodingHint::APPLICATION_OCTET_STREAM
        }
    }

    /// Read the value at `target`, if there is one.
    fn read_value(&self, target: &Path) -> Result<Option<StoredData>, ReadFailure> {
        let Some(file) = self.locate(target) else {
            return Ok(None);
        };
        let payload = fs::read(&file).map_err(|e| ReadFailure::Io(file.clone(), e))?;
        let DataInfo {
            encoding,
            timestamp,
        } = self.metadata_of(&file)?;
        Ok(Some(StoredData {
            payload,
            encoding,
            timestamp,
        }))
    }

    /// The timestamp of the value at `target`, without reading its payload --
    /// what a listing needs, and why upstream has `read_timestamp` beside
    /// `read_file`.
    fn read_timestamp(&self, target: &Path) -> Result<Option<TimestampHint>, ReadFailure> {
        match self.locate(target) {
            Some(file) => Ok(Some(self.metadata_of(&file)?.timestamp)),
            None => Ok(None),
        }
    }

    /// `fsync` a directory — the step that makes an entry in it durable. The one
    /// place [`fail_dir_sync`](Self::fail_dir_sync) is read.
    fn dir_sync(&self, dir: &Path) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_dir_sync {
            return Err(io::Error::other("injected dir fsync failure (R2382)"));
        }
        fsync_dir(dir)
    }

    /// Unlink a key's file. The one place the test-only `fail_unlink` is read.
    fn unlink(&self, file: &Path) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_unlink {
            return Err(io::Error::other("injected unlink failure (R2801)"));
        }
        fs::remove_file(file)
    }

    /// Create every missing directory from the base directory down to `dir`,
    /// each `fsync`ed into its parent so the path to a committed value survives
    /// a power loss.
    fn create_dirs(&self, dir: &Path) -> io::Result<()> {
        let mut missing = Vec::new();
        let mut cursor = dir;
        while !cursor.is_dir() {
            missing.push(cursor.to_path_buf());
            match cursor.parent() {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
        for created in missing.iter().rev() {
            match fs::create_dir(created) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && created.is_dir() => continue,
                Err(e) => return Err(e),
            }
            if let Some(parent) = created.parent() {
                self.dir_sync(parent)?;
            }
        }
        Ok(())
    }

    /// Make room for a directory at every ancestor of `target` that is a FILE:
    /// that file is a shorter key's value, and it moves to its conflict name,
    /// its sidecar row with it. Upstream's `write_file` prologue.
    ///
    /// A file with no row keeps none after the move, which is upstream's net
    /// effect: its fallback there writes a row under the NEW key's path, which
    /// the new key's own row then overwrites.
    fn move_ancestor_files_aside(&self, target: &Path) -> Result<(), WriteFailure> {
        let Some(parent) = target.parent() else {
            return Ok(());
        };
        for ancestor in parent.ancestors() {
            if ancestor.is_dir() {
                break;
            }
            if ancestor.is_file() {
                let aside = conflict_path(ancestor);
                let io_failure = |what, err| WriteFailure::Io {
                    what,
                    path: ancestor.to_path_buf(),
                    err,
                    landed: false,
                };
                fs::rename(ancestor, &aside)
                    .map_err(|e| io_failure("move a shorter key's file aside", e))?;
                if let Some(dir) = ancestor.parent() {
                    self.dir_sync(dir)
                        .map_err(|e| io_failure("persist the move of a shorter key's file", e))?;
                }
                self.data_info
                    .rename(ancestor, &aside)
                    .map_err(WriteFailure::DataInfo)?;
            }
        }
        Ok(())
    }

    /// Write `payload` so that `file` names it only once it is complete:
    /// staging file, `fsync`, `rename`, `fsync` of the directory naming it.
    fn write_payload(&self, file: &Path, payload: &[u8]) -> Result<(), WriteFailure> {
        let failure = |what, path: &Path, err, landed| WriteFailure::Io {
            what,
            path: path.to_path_buf(),
            err,
            landed,
        };
        let staging = self.base_dir.join(STAGING_DIR);
        self.create_dirs(&staging)
            .map_err(|e| failure("create the staging area", &staging, e, false))?;
        let staged = staging.join(format!(
            "{}.{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let write_staged = || -> io::Result<()> {
            let mut f = fs::File::create(&staged)?;
            f.write_all(payload)?;
            f.sync_all()
        };
        if let Err(e) = write_staged() {
            let _ = fs::remove_file(&staged);
            return Err(failure("write the staged payload", &staged, e, false));
        }
        if let Err(e) = fs::rename(&staged, file) {
            let _ = fs::remove_file(&staged);
            return Err(failure("rename the payload into place", file, e, false));
        }
        // The rename LANDED: the key's path now names the new bytes, and only
        // the durability of that entry is unconfirmed.
        let dir = file.parent().unwrap_or(&self.base_dir);
        self.dir_sync(dir)
            .map_err(|e| failure("persist the payload's directory entry", dir, e, true))
    }

    /// Place a value at `target`: move shorter keys' files aside, create the
    /// directories, take the conflict name when `target` is itself a directory,
    /// write the payload, then its row -- in that order, for the reason the
    /// module note gives.
    fn write_value(
        &self,
        target: &Path,
        payload: &[u8],
        row: &DataInfo,
    ) -> Result<(), WriteFailure> {
        self.move_ancestor_files_aside(target)?;
        if let Some(parent) = target.parent() {
            self.create_dirs(parent).map_err(|e| WriteFailure::Io {
                what: "create the key's directories",
                path: parent.to_path_buf(),
                err: e,
                landed: false,
            })?;
        }
        let file = if target.is_dir() {
            conflict_path(target)
        } else {
            target.to_path_buf()
        };
        self.write_payload(&file, payload)?;
        self.data_info
            .put(&file, row)
            .map_err(WriteFailure::DataInfo)
    }

    /// Remove every file that holds the value placed at `target`, and their
    /// rows; `Ok(false)` when a removal is not confirmed durable.
    ///
    /// ⚠ EVERY holder, where upstream removes one. The suffix scheme can leave a
    /// key's value in two places -- `a.##z` written while `a/` was a directory,
    /// then `a` written after that directory emptied -- and reads prefer `a`, so
    /// removing only `a` would make the older `a.##z` the key's value again: a
    /// deleted key coming back with a stale value. A delete removes the key.
    fn delete_value(&self, target: &Path) -> Result<bool, WriteFailure> {
        let mut durable = true;
        for file in [target.to_path_buf(), conflict_path(target)] {
            if file.is_file() {
                match self.unlink(&file) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(WriteFailure::Io {
                            what: "remove the key's file",
                            path: file,
                            err: e,
                            landed: false,
                        })
                    }
                }
                let dir = file.parent().unwrap_or(&self.base_dir);
                if let Err(e) = self.dir_sync(dir) {
                    log::error!(
                        "wz-fs-storage: dir fsync after removing {} failed ({e}); the file is \
                         gone but its removal is not confirmed durable",
                        file.display()
                    );
                    durable = false;
                }
                self.prune_empty_parents(&file);
            }
            // Upstream forgets the row whether or not a file was there; so does
            // this, for both names.
            self.data_info
                .delete(&file)
                .map_err(WriteFailure::DataInfo)?;
        }
        Ok(durable)
    }

    /// Remove the directories a delete emptied, up to (never including) the
    /// base directory. Upstream's loop. Not fsynced: an empty directory that
    /// reappears after a crash holds no key.
    fn prune_empty_parents(&self, file: &Path) {
        let mut cursor = file;
        while let Some(parent) = cursor.parent() {
            if parent == self.base_dir || fs::remove_dir(parent).is_err() {
                break;
            }
            cursor = parent;
        }
    }

    /// Walk the tree and list every key it holds with its timestamp -- the body
    /// of [`get_all_entries`](StorageBackend::get_all_entries).
    ///
    /// The walk's rules are upstream's: the sidecar directory is skipped by
    /// name, a path counts only when its trimmed form is a listable key
    /// ([`is_listable_key`]), and a link below the base directory is followed
    /// only when [`follow_links`](FilesystemOptions::follow_links) says so.
    /// Failing to read the base directory itself refuses the listing -- a store
    /// that cannot list must not open as an empty one (R2800) -- while a failure
    /// on one entry is logged and skipped, as upstream skips it, so one bad file
    /// never hides every other key.
    ///
    /// ⚠ One divergence: upstream refuses to walk at all when the directory it
    /// searches is itself a link and links are not followed -- and it searches
    /// the base directory, which [`contains_symlink`](Self::contains_symlink)
    /// otherwise does not mind. So upstream SERVES the files of a linked base
    /// directory by key and LISTS none of them. This store minds links below the
    /// base directory, for reads and listing alike, so the two cannot disagree.
    fn list(&self) -> Result<BTreeMap<String, TimestampHint>, ReadFailure> {
        let mut keys = BTreeMap::new();
        let mut walk = walkdir::WalkDir::new(&self.base_dir)
            .follow_links(self.options.follow_links)
            .into_iter();
        while let Some(entry) = walk.next() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.depth() == 0 => {
                    return Err(ReadFailure::Io(
                        self.base_dir.clone(),
                        e.into_io_error()
                            .unwrap_or_else(|| io::Error::other("unreadable base directory")),
                    ))
                }
                Err(e) => {
                    log::debug!("wz-fs-storage: skipping an unreadable entry ({e})");
                    continue;
                }
            };
            if entry.file_type().is_dir() {
                if entry.depth() == 1
                    && (entry.file_name() == DB_FILENAME || entry.file_name() == STAGING_DIR)
                {
                    walk.skip_current_dir();
                }
                continue;
            }
            let Ok(relative) = entry.path().strip_prefix(&self.base_dir) else {
                continue;
            };
            let Some(relative) = relative.to_str() else {
                log::debug!(
                    "wz-fs-storage: ignoring a non-UTF-8 file name {}",
                    entry.path().display()
                );
                continue;
            };
            let coarse = relpath_to_zkey(relative);
            let zkey = trimmed_key(&coarse);
            if !is_listable_key(zkey) {
                continue;
            }
            let target = self.base_dir.join(zkey_to_relpath(zkey).as_ref());
            match self.read_timestamp(&target) {
                Ok(Some(timestamp)) => {
                    keys.insert(zkey.to_string(), timestamp);
                }
                Ok(None) => {}
                Err(e) => log::warn!("wz-fs-storage: listing skips {zkey:?}: {e}"),
            }
        }
        Ok(keys)
    }
}

/// Why a read could not be served. Logged by the backend; the seam carries the
/// payload-free [`StorageReadError`].
#[derive(Debug)]
enum ReadFailure {
    Io(PathBuf, io::Error),
    DataInfo(DataInfoError),
    FileTime(PathBuf, &'static str),
}

impl core::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReadFailure::Io(path, e) => write!(f, "cannot read {}: {e}", path.display()),
            ReadFailure::DataInfo(e) => write!(f, "{e}"),
            ReadFailure::FileTime(path, why) => {
                write!(f, "no timestamp for {}: {why}", path.display())
            }
        }
    }
}

/// Why a mutation could not be committed. Logged by the backend; the seam
/// carries the payload-free [`StorageWriteError`].
#[derive(Debug)]
enum WriteFailure {
    /// A filesystem step failed. `landed` says whether the key's path already
    /// names the new state -- which no longer moves anything in this store (a
    /// read shows the directory either way) and is kept for the operator, who
    /// needs to know whether the old value is still there.
    Io {
        what: &'static str,
        path: PathBuf,
        err: io::Error,
        landed: bool,
    },
    DataInfo(DataInfoError),
}

impl core::fmt::Display for WriteFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WriteFailure::Io {
                what,
                path,
                err,
                landed,
            } => write!(
                f,
                "cannot {what} ({}): {err}; {}",
                path.display(),
                if *landed {
                    "the new bytes are in place but not confirmed durable"
                } else {
                    "the stored value is unchanged"
                }
            ),
            WriteFailure::DataInfo(e) => write!(f, "{e}"),
        }
    }
}

impl StorageBackend for FilesystemStorage {
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        let Some(target) = self.key_path(key) else {
            log::error!("wz-fs-storage: refusing to place key {key:?} (see `key_path`)");
            return Err(StorageWriteError);
        };
        // ⚠ A divergence in the safe direction: upstream's write path never
        // looks for links, so with `follow_links` off it writes THROUGH one --
        // out of its own tree -- and then refuses to read back what it wrote.
        // This store refuses the write instead, so what it accepts is what it
        // serves.
        if !self.options.follow_links && self.contains_symlink(&target) {
            log::error!(
                "wz-fs-storage: refusing key {key:?}: its path passes through a link and \
                 `follow_links` is off"
            );
            return Err(StorageWriteError);
        }
        let row = DataInfo {
            encoding,
            timestamp,
        };
        // A row the sidecar cannot hold is refused BEFORE the payload moves, so
        // a refused put leaves the previous value exactly as it was.
        if let Err(e) = filesystem_datainfo::encode(&row) {
            log::error!("wz-fs-storage: refusing key {key:?}: {e}");
            return Err(StorageWriteError);
        }
        let existed = self.locate(&target).is_some();
        match self.write_value(&target, &payload, &row) {
            Ok(()) if existed => Ok(StorageInsertionResult::Replaced),
            Ok(()) => Ok(StorageInsertionResult::Inserted),
            Err(e) => {
                log::error!("wz-fs-storage: put of key {key:?} is NOT committed: {e}");
                Err(StorageWriteError)
            }
        }
    }

    fn delete(&mut self, key: Option<&str>, _timestamp: TimestampHint) -> StorageWriteResult {
        // A key that cannot be placed holds nothing, and an absent-key delete is
        // `Deleted` -- the seam contract, and upstream's `if file.exists()`.
        let Some(target) = self.key_path(key) else {
            return Ok(StorageInsertionResult::Deleted);
        };
        match self.delete_value(&target) {
            Ok(true) => Ok(StorageInsertionResult::Deleted),
            Ok(false) => Err(StorageWriteError),
            Err(e) => {
                log::error!("wz-fs-storage: delete of key {key:?} is NOT committed: {e}");
                Err(StorageWriteError)
            }
        }
    }

    fn get(&self, key: Option<&str>) -> Result<Vec<StoredData>, StorageReadError> {
        // A key that cannot be placed was never stored.
        let Some(target) = self.key_path(key) else {
            return Ok(Vec::new());
        };
        self.read_value(&target)
            .map(|value| value.into_iter().collect())
            .map_err(|e| {
                log::error!("wz-fs-storage: get of key {key:?} failed: {e}");
                StorageReadError
            })
    }

    fn get_all_entries(&self) -> Result<Vec<(Option<String>, TimestampHint)>, StorageReadError> {
        let refuse = |e: ReadFailure| {
            log::error!(
                "wz-fs-storage: cannot list {}: {e}",
                self.base_dir.display()
            );
            StorageReadError
        };
        let mut entries = Vec::new();
        // The mount-point key first. A walk never lists it (`@root` is a
        // verbatim chunk), so it is read by name, and -- as upstream's `?` does
        // there -- a failure to read it refuses the listing.
        if let Some(timestamp) = self
            .read_timestamp(&self.base_dir.join(ROOT_KEY))
            .map_err(refuse)?
        {
            entries.push((None, timestamp));
        }
        entries.extend(
            self.list()
                .map_err(refuse)?
                .into_iter()
                .map(|(k, t)| (Some(k), t)),
        );
        Ok(entries)
    }
    // history() defaults to History::Latest — upstream's fs volume advertises
    // `History::Latest` too; History::All is the separate `storage-history` atom.
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
        // Config-agnostic beyond `name` until the next round maps upstream's
        // per-storage properties (`dir`, `read_only`, `on_closure`,
        // `follow_links`, `keep_mime_types`) off `volume_cfg`.
        FilesystemStorage::open(self.root.join(&config.name))
            .map(|s| Box::new(s) as Box<dyn StorageBackend + Send>)
            .map_err(|e| VolumeError::CreateFailed(e.to_string()))
    }
}

/// The name a key's value takes when its own path is a directory.
fn conflict_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(CONFLICT_SUFFIX);
    PathBuf::from(name)
}

/// Whether `path` itself is a symbolic link (not following it).
fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// The timestamp upstream gives a file that was not put through zenoh: its
/// modification time (else access, else creation, else now) as NTP64, stamped
/// with the id `[1]`.
///
/// ⚠ Two upstream PANICS are refusals here, as elsewhere in this tree: a time
/// before the epoch (`duration_since(..).unwrap()`) and one past the NTP64
/// seconds range (uhlc's `assert!` in `From<Duration>`). A file time must not be
/// able to take a node down; either reads as a refusal of that one file.
fn file_time_timestamp(file: &Path) -> Result<TimestampHint, ReadFailure> {
    let meta = fs::metadata(file).map_err(|e| ReadFailure::Io(file.to_path_buf(), e))?;
    let when = meta
        .modified()
        .or_else(|_| meta.accessed())
        .or_else(|_| meta.created())
        .unwrap_or_else(|_| SystemTime::now());
    let since = when
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReadFailure::FileTime(file.to_path_buf(), "its time is before the epoch"))?;
    if since.as_secs() > u64::from(u32::MAX) {
        return Err(ReadFailure::FileTime(
            file.to_path_buf(),
            "its time is past the NTP64 seconds range",
        ));
    }
    Ok(TimestampHint {
        time: Ntp64::from_unix(since.as_secs(), since.subsec_nanos()).as_word(),
        zid: FILE_TIME_ZID.to_vec(),
    })
}

/// `fsync` a directory so an entry created, renamed or removed in it is
/// persisted (on Linux, opening the directory read-only and `sync_all`-ing its
/// fd flushes the directory entry).
fn fsync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
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
            packed_id: (4 << 1) | 1,
            schema: Some("utf-8".to_string()),
        })
    }

    fn open(dir: &Path) -> FilesystemStorage {
        FilesystemStorage::open(dir.to_path_buf()).unwrap()
    }

    fn payload_of(s: &FilesystemStorage, key: Option<&str>) -> Option<Vec<u8>> {
        s.get_newest(key).unwrap().map(|d| d.payload)
    }

    // ---- the SHAPE: the directory mirrors the key space ----

    /// The atom's own claim, read off the directory rather than through the
    /// backend: a key IS a path, and the file there holds exactly the payload.
    #[test]
    fn a_key_is_a_file_at_its_path_holding_exactly_the_payload() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("demo/a/b"), b"hello".to_vec(), enc(), ts(10))
            .unwrap();
        assert_eq!(fs::read(dir.path().join("demo/a/b")).unwrap(), b"hello");
        s.put(None, b"root".to_vec(), None, ts(11)).unwrap();
        assert_eq!(fs::read(dir.path().join(ROOT_KEY)).unwrap(), b"root");
    }

    /// The other direction: a file nobody put through zenoh is a value, with
    /// upstream's fallbacks -- the encoding its extension names, the timestamp
    /// its modification time gives, stamped with the id `[1]`.
    #[test]
    fn a_file_dropped_into_the_tree_is_served_with_upstreams_fallbacks() {
        let dir = tempdir().unwrap();
        let s = open(dir.path());
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("docs/readme.json"), b"{}").unwrap();

        let got = s.get_newest(Some("docs/readme.json")).unwrap().unwrap();
        assert_eq!(got.payload, b"{}");
        assert_eq!(got.encoding, Some(EncodingHint::APPLICATION_JSON));
        assert_eq!(got.timestamp.zid, FILE_TIME_ZID.to_vec());
        let mtime = fs::metadata(dir.path().join("docs/readme.json"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap();
        assert_eq!(
            got.timestamp.time,
            Ntp64::from_unix(mtime.as_secs(), mtime.subsec_nanos()).as_word()
        );
        assert_eq!(
            s.get_all_entries().unwrap(),
            vec![(Some("docs/readme.json".to_string()), got.timestamp)]
        );
    }

    #[test]
    fn keep_mime_types_off_serves_an_unrecorded_file_as_octet_stream() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("page.json"), b"{}").unwrap();
        let s = FilesystemStorage::open_with(
            dir.path().to_path_buf(),
            FilesystemOptions {
                keep_mime_types: false,
                ..FilesystemOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.get_newest(Some("page.json")).unwrap().unwrap().encoding,
            Some(EncodingHint::APPLICATION_OCTET_STREAM)
        );
    }

    #[test]
    fn a_recorded_value_keeps_its_own_encoding_whatever_its_extension_says() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("x.json"), b"plain".to_vec(), enc(), ts(10))
            .unwrap();
        assert_eq!(
            s.get_newest(Some("x.json")).unwrap().unwrap().encoding,
            enc()
        );
    }

    // ---- prefix conflicts: a key that is also a directory ----

    #[test]
    fn a_shorter_key_written_first_moves_aside_with_its_row() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("a"), b"short".to_vec(), enc(), ts(10)).unwrap();
        s.put(Some("a/b"), b"long".to_vec(), None, ts(11)).unwrap();

        assert!(dir.path().join("a").is_dir());
        assert_eq!(
            fs::read(dir.path().join(format!("a{CONFLICT_SUFFIX}"))).unwrap(),
            b"short"
        );
        let short = s.get_newest(Some("a")).unwrap().unwrap();
        assert_eq!(short.payload, b"short");
        assert_eq!(short.encoding, enc(), "the row moved with the file");
        assert_eq!(short.timestamp, ts(10));
        assert_eq!(payload_of(&s, Some("a/b")), Some(b"long".to_vec()));
        assert_eq!(
            s.get_all_entries().unwrap(),
            vec![
                (Some("a".to_string()), ts(10)),
                (Some("a/b".to_string()), ts(11)),
            ]
        );
    }

    #[test]
    fn a_shorter_key_written_second_takes_the_conflict_name() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("a/b"), b"long".to_vec(), None, ts(10)).unwrap();
        assert_eq!(
            s.put(Some("a"), b"short".to_vec(), None, ts(11)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            fs::read(dir.path().join(format!("a{CONFLICT_SUFFIX}"))).unwrap(),
            b"short"
        );
        assert_eq!(payload_of(&s, Some("a")), Some(b"short".to_vec()));
    }

    /// The divergence `delete_value` names: after `a/` empties, `a` is written
    /// unsuffixed while the older `a.##z` is still there, and a delete that
    /// removed only one would resurrect the other.
    #[test]
    fn a_delete_removes_every_file_holding_the_key_and_prunes_empty_dirs() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("a/b"), b"long".to_vec(), None, ts(10)).unwrap();
        s.put(Some("a"), b"old".to_vec(), None, ts(11)).unwrap();
        s.delete(Some("a/b"), ts(12)).unwrap();
        assert!(
            !dir.path().join("a").exists(),
            "the emptied directory is pruned"
        );
        s.put(Some("a"), b"new".to_vec(), None, ts(13)).unwrap();
        assert_eq!(payload_of(&s, Some("a")), Some(b"new".to_vec()));

        s.delete(Some("a"), ts(14)).unwrap();
        assert_eq!(
            payload_of(&s, Some("a")),
            None,
            "the stale conflict-named value must not come back"
        );
        assert!(s.get_all_entries().unwrap().is_empty());
    }

    // ---- what a walk lists ----

    #[test]
    fn a_listing_skips_the_sidecar_the_staging_area_and_non_keys() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), b"v".to_vec(), None, ts(10)).unwrap();
        fs::create_dir_all(dir.path().join(STAGING_DIR)).unwrap();
        fs::write(dir.path().join(STAGING_DIR).join("1.0"), b"debris").unwrap();
        fs::write(dir.path().join("not#a#key"), b"x").unwrap();
        assert!(dir.path().join(DB_FILENAME).is_dir());
        assert_eq!(
            s.get_all_entries().unwrap(),
            vec![(Some("k".to_string()), ts(10))]
        );
    }

    #[test]
    fn opening_clears_what_a_crash_left_in_the_staging_area() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(STAGING_DIR)).unwrap();
        fs::write(dir.path().join(STAGING_DIR).join("99.0"), b"debris").unwrap();
        let _s = open(dir.path());
        assert!(!dir.path().join(STAGING_DIR).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_path_is_served_listed_and_written_only_when_links_are_followed() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"s").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();

        {
            let mut s = open(dir.path());
            assert_eq!(payload_of(&s, Some("linked/secret")), None);
            assert!(s.get_all_entries().unwrap().is_empty());
            assert!(
                s.put(Some("linked/new"), b"n".to_vec(), None, ts(1))
                    .is_err(),
                "a write through a link it would not read back is refused"
            );
            assert!(!outside.path().join("new").exists());
        }
        let s = FilesystemStorage::open_with(
            dir.path().to_path_buf(),
            FilesystemOptions {
                follow_links: true,
                ..FilesystemOptions::default()
            },
        )
        .unwrap();
        assert_eq!(payload_of(&s, Some("linked/secret")), Some(b"s".to_vec()));
        assert_eq!(s.get_all_entries().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_base_directory_that_is_itself_a_link_still_lists() {
        // The divergence `list` names: upstream serves a linked base
        // directory's files by key and lists none of them.
        let real = tempdir().unwrap();
        let holder = tempdir().unwrap();
        let link = holder.path().join("store");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let mut s = open(&link);
        s.put(Some("k"), b"v".to_vec(), None, ts(10)).unwrap();
        assert_eq!(payload_of(&s, Some("k")), Some(b"v".to_vec()));
        assert_eq!(s.get_all_entries().unwrap().len(), 1);
    }

    // ---- refusals ----

    #[test]
    fn a_key_that_would_leave_or_alias_the_store_is_refused() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        for bad in [
            "../escape",
            "a/../../escape",
            "/abs",
            "",
            ROOT_KEY,
            ".zenoh_datainfo/x",
            "@wz_staging/x",
            // Not a key expression, and it would read back as the key `x`.
            "x.##z",
        ] {
            assert!(
                s.put(Some(bad), b"x".to_vec(), None, ts(1)).is_err(),
                "{bad:?} must be refused"
            );
            assert_eq!(payload_of(&s, Some(bad)), None);
        }
        assert!(!dir.path().parent().unwrap().join("escape").exists());
        assert!(s.get_all_entries().unwrap().is_empty());
    }

    #[test]
    fn a_timestamp_the_sidecar_cannot_hold_is_refused_before_the_payload_moves() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), b"v1".to_vec(), None, ts(10)).unwrap();
        let empty_zid = TimestampHint {
            time: 20,
            zid: vec![],
        };
        assert!(s.put(Some("k"), b"v2".to_vec(), None, empty_zid).is_err());
        assert_eq!(payload_of(&s, Some("k")), Some(b"v1".to_vec()));
    }

    // ---- in-process seam parity (mirror of MemoryStorage's contract) ----

    #[test]
    fn put_get_roundtrip_and_replace() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        assert_eq!(
            s.put(Some("demo/a"), vec![1, 2, 3], None, ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(payload_of(&s, Some("demo/a")), Some(vec![1, 2, 3]));
        assert_eq!(
            s.put(Some("demo/a"), vec![4], None, ts(20)).unwrap(),
            StorageInsertionResult::Replaced
        );
        let got = s.get(Some("demo/a")).unwrap();
        assert_eq!(got.len(), 1, "a Latest store holds one version");
        assert_eq!(got[0].payload, vec![4]);
        assert_eq!(got[0].timestamp, ts(20));
        assert_eq!(
            got[0].encoding, None,
            "the default encoding round-trips as none"
        );
    }

    #[test]
    fn delete_removes_and_absent_delete_is_deleted() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        assert_eq!(
            s.delete(Some("demo/a"), ts(20)).unwrap(),
            StorageInsertionResult::Deleted
        );
        assert_eq!(payload_of(&s, Some("demo/a")), None);
        assert_eq!(
            s.delete(Some("demo/missing"), ts(1)).unwrap(),
            StorageInsertionResult::Deleted
        );
    }

    #[test]
    fn none_root_slot_is_independent_and_lists_first() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        s.put(None, vec![9], None, ts(20)).unwrap();
        assert_eq!(payload_of(&s, None), Some(vec![9]));
        assert_eq!(payload_of(&s, Some("demo/a")), Some(vec![1]));
        assert_eq!(
            s.get_all_entries().unwrap(),
            vec![(None, ts(20)), (Some("demo/a".to_string()), ts(10))]
        );
    }

    // ---- durability (the atom's whole point) ----

    #[test]
    fn durability_survives_reopen_with_encoding_and_timestamp() {
        let dir = tempdir().unwrap();
        {
            let mut s = open(dir.path());
            s.put(Some("demo/a"), vec![1, 2, 3], enc(), ts(10)).unwrap();
            s.put(Some("wild/*/x"), vec![9], None, ts(11)).unwrap();
            s.put(None, vec![0xff], None, ts(12)).unwrap();
            s.put(Some("to/delete"), vec![5], None, ts(13)).unwrap();
            s.delete(Some("to/delete"), ts(14)).unwrap();
        } // drop -> a fresh instance sees only what is on disk
        let s = open(dir.path());
        let a = s.get_newest(Some("demo/a")).unwrap().unwrap();
        assert_eq!(a.payload, vec![1, 2, 3]);
        assert_eq!(a.encoding, enc());
        assert_eq!(a.timestamp, ts(10));
        assert_eq!(payload_of(&s, Some("wild/*/x")), Some(vec![9]));
        assert_eq!(payload_of(&s, None), Some(vec![0xff]));
        assert_eq!(
            payload_of(&s, Some("to/delete")),
            None,
            "delete must persist"
        );
    }

    #[test]
    fn a_deep_key_persists_past_the_canonizers_bound() {
        let dir = tempdir().unwrap();
        let key = "k/".to_string() + &"segment/".repeat(64) + "leaf"; // ~530 bytes
        {
            let mut s = open(dir.path());
            s.put(Some(&key), vec![42], None, ts(1)).unwrap();
        }
        let s = open(dir.path());
        assert_eq!(payload_of(&s, Some(&key)), Some(vec![42]));
        assert_eq!(s.get_all_entries().unwrap(), vec![(Some(key), ts(1))]);
    }

    #[test]
    fn a_second_live_store_on_the_same_directory_is_refused() {
        let dir = tempdir().unwrap();
        let first = open(dir.path());
        assert!(FilesystemStorage::open(dir.path().to_path_buf()).is_err());
        drop(first);
        assert!(FilesystemStorage::open(dir.path().to_path_buf()).is_ok());
    }

    // ---- write failure: what a store that could not persist may claim ----

    /// R2382, restated for a store with no copy -- and the proof of the
    /// payload-before-row ORDER the module note argues for. The first put makes
    /// every directory the second needs, so the second's only directory sync is
    /// the one AFTER its rename: the rename lands, that sync fails.
    ///
    /// Three halves: the caller is refused (nothing above records the put); a
    /// read shows the NEW bytes, because the directory names them; and it shows
    /// them under the PREVIOUS row's timestamp, because the row is written only
    /// after the payload is durable. Row-first would read back `ts(20)` here.
    #[test]
    fn a_landed_write_whose_dir_fsync_failed_is_refused_and_keeps_the_older_row() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), vec![1], None, ts(10)).unwrap();
        let mut s = s.with_failing_dir_sync();

        let outcome = s.put(Some("k"), vec![2], None, ts(20));
        assert!(outcome.is_err(), "not committed; got {outcome:?}");
        let got = s.get_newest(Some("k")).unwrap().unwrap();
        assert_eq!(
            got.payload,
            vec![2],
            "the rename landed; a read is the disk"
        );
        assert_eq!(
            got.timestamp,
            ts(10),
            "the row follows the payload, so an unconfirmed payload keeps the older row"
        );
    }

    /// R2382 ANTI-VACUITY twin: the SAME second write without the injection
    /// commits and moves the row, so the test above cannot pass against a store
    /// that never moves rows or never commits.
    #[test]
    fn the_same_write_without_the_injection_commits_and_moves_the_row() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), vec![1], None, ts(10)).unwrap();
        assert_eq!(
            s.put(Some("k"), vec![2], None, ts(20)).unwrap(),
            StorageInsertionResult::Replaced,
        );
        assert_eq!(s.get_newest(Some("k")).unwrap().unwrap().timestamp, ts(20));
    }

    #[test]
    fn a_put_whose_staging_write_fails_leaves_the_previous_value() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), vec![1], None, ts(10)).unwrap();
        // A FILE where the staging directory goes: creating it fails for every
        // uid, root included.
        fs::remove_dir_all(dir.path().join(STAGING_DIR)).unwrap();
        fs::write(dir.path().join(STAGING_DIR), b"in the way").unwrap();
        assert!(s.put(Some("k"), vec![2], None, ts(20)).is_err());
        let got = s.get_newest(Some("k")).unwrap().unwrap();
        assert_eq!(got.payload, vec![1]);
        assert_eq!(got.timestamp, ts(10));
    }

    #[test]
    fn a_delete_whose_unlink_fails_keeps_serving_the_key() {
        let dir = tempdir().unwrap();
        let mut s = open(dir.path());
        s.put(Some("k"), vec![1], None, ts(10)).unwrap();
        let mut s = s.with_failing_unlink();
        assert!(s.delete(Some("k"), ts(20)).is_err());
        assert_eq!(payload_of(&s, Some("k")), Some(vec![1]));
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
            s.get_newest(Some("demo/a")).unwrap().unwrap().payload,
            vec![1, 2, 3],
            "a storage re-created over the same name reloads its data"
        );
        let other = vol
            .create_storage(&StorageConfig::new("other", "o/**", "fs"))
            .unwrap();
        assert!(other.get_newest(Some("demo/a")).unwrap().is_none());
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

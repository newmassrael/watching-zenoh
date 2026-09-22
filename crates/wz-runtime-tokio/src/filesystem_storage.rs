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
//! [`get`](wz_session_core::storage_backend::StorageBackend::get) opens the
//! key's file, and
//! [`get_all_entries`](wz_session_core::storage_backend::StorageBackend::get_all_entries)
//! walks the tree. That is
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
//! directory ([`STAGING_DIR`](crate::filesystem_keypath::STAGING_DIR)), `fsync`s
//! it, `rename`s it over the key's path,
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
use wz_session_core::json5::Json5Value;
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

/// The environment variable that names the root of every storage this volume
/// creates — byte for byte upstream's `SCOPE_ENV_VAR`.
pub const SCOPE_ENV_VAR: &str = "ZENOH_BACKEND_FS_ROOT";

/// The root under the zenoh home directory when [`SCOPE_ENV_VAR`] is unset —
/// upstream's `DEFAULT_ROOT_DIR`.
pub const DEFAULT_ROOT_DIR: &str = "zenoh_backend_fs";

/// The environment variable naming the zenoh home directory, and the directory
/// used under the user's home when it is unset — upstream's `zenoh_home()`
/// (`commons/zenoh-util/src/lib.rs` @ `pub fn zenoh_home() -> &'static std::path::Path {`).
pub const ZENOH_HOME_ENV_VAR: &str = "ZENOH_HOME";
/// See [`ZENOH_HOME_ENV_VAR`].
pub const DEFAULT_ZENOH_HOME_DIRNAME: &str = ".zenoh";

/// The per-storage properties, by upstream's names (its `PROP_STORAGE_*`).
pub const PROP_STORAGE_READ_ONLY: &str = "read_only";
/// See [`PROP_STORAGE_READ_ONLY`].
pub const PROP_STORAGE_DIR: &str = "dir";
/// See [`PROP_STORAGE_READ_ONLY`].
pub const PROP_STORAGE_ON_CLOSURE: &str = "on_closure";
/// See [`PROP_STORAGE_READ_ONLY`].
pub const PROP_STORAGE_FOLLOW_LINK: &str = "follow_links";
/// See [`PROP_STORAGE_READ_ONLY`].
pub const PROP_STORAGE_KEEP_MIME: &str = "keep_mime_types";
/// The key upstream inserts into a storage's `volume_cfg` naming the directory
/// it resolved, so the admin plane shows where the data is.
pub const DIR_FULL_PATH: &str = "dir_full_path";

/// What a storage does to its directory when it closes — upstream's
/// `OnClosure`, read from `on_closure` (`"do_nothing"` by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnClosure {
    /// Leave the directory, its files and its sidecar as they are.
    #[default]
    DoNothing,
    /// Remove the whole directory, sidecar included, once the storage is gone.
    DeleteAll,
}

/// A storage's properties, named and defaulted as upstream's fs volume names
/// and defaults them (`follow_links` false, `keep_mime_types` true,
/// `read_only` false, `on_closure` do-nothing).
///
/// `follow_links` and `keep_mime_types` are here because the directory-tree
/// layout gives them something to decide -- with the old hashed layout there
/// was no link to follow and no extension to read. [`FilesystemVolume`] reads
/// all four off a storage's `volume_cfg` (R2802); `dir`, the fifth property,
/// is not an option of a store but the choice of which directory it is.
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
    /// Refuse every put and delete; the directory is served as it is.
    pub read_only: bool,
    /// What happens to the directory when the store is dropped.
    pub on_closure: OnClosure,
}

impl Default for FilesystemOptions {
    fn default() -> Self {
        Self {
            follow_links: false,
            keep_mime_types: true,
            read_only: false,
            on_closure: OnClosure::DoNothing,
        }
    }
}

/// Removes a store's directory when the store is dropped, if its
/// [`OnClosure`] says so.
///
/// A FIELD rather than `FilesystemStorage`'s own `Drop`, and the last one: Rust
/// drops fields in declaration order, so the sidecar has closed -- and released
/// its lock -- before this runs. Upstream closes its data-info database first
/// for the same reason.
#[derive(Debug)]
struct ClosureGuard {
    base_dir: PathBuf,
    on_closure: OnClosure,
}

impl Drop for ClosureGuard {
    fn drop(&mut self) {
        if self.on_closure == OnClosure::DeleteAll {
            if let Err(e) = fs::remove_dir_all(&self.base_dir) {
                log::warn!(
                    "wz-fs-storage: failed to clean up {} on closure ({e})",
                    self.base_dir.display()
                );
            }
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
    /// LAST, so it runs after the sidecar has closed (see [`ClosureGuard`]).
    /// Held only for its `Drop`, which is what the leading underscore says.
    _closure: ClosureGuard,
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
            _closure: ClosureGuard {
                base_dir: dir.clone(),
                on_closure: options.on_closure,
            },
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
        // Upstream's `read_only` arm: a warning and a refusal, nothing touched.
        if self.options.read_only {
            log::warn!(
                "wz-fs-storage: PUT of {key:?} refused: the storage on {} is read-only",
                self.base_dir.display()
            );
            return Err(StorageWriteError);
        }
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
        if self.options.read_only {
            log::warn!(
                "wz-fs-storage: DELETE of {key:?} refused: the storage on {} is read-only",
                self.base_dir.display()
            );
            return Err(StorageWriteError);
        }
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

/// A durable [`Volume`] that creates one [`FilesystemStorage`] per storage,
/// each in the directory its `dir` property names under the volume's root. The
/// wz counterpart of zenoh's `zenoh-backend-filesystem` volume;
/// [`capability`](Volume::capability) advertises `{ Durable, Latest }`.
///
/// # The root, and why it is canonical
///
/// [`FilesystemVolume::from_env`] derives the root as upstream's plugin does:
/// [`SCOPE_ENV_VAR`] when set, else [`DEFAULT_ROOT_DIR`] under the zenoh home
/// ([`ZENOH_HOME_ENV_VAR`], else [`DEFAULT_ZENOH_HOME_DIRNAME`] under the user's
/// home), created and then CANONICALIZED. [`FilesystemVolume::new`] takes a
/// root from the host instead, a wz extension, and canonicalizes it the same
/// way when a storage is created. The canonical form is not cosmetic: the
/// sidecar keys each row by the file's full path, so a directory is served
/// with its metadata by wz and by zenohd alike only when both spell its path
/// the same way.
#[derive(Debug, Clone)]
pub struct FilesystemVolume {
    root: PathBuf,
}

impl FilesystemVolume {
    /// A filesystem volume whose storages live under `root`, which the host
    /// chose.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// A filesystem volume rooted where upstream's plugin roots it (see the
    /// type's doc), or the reason that root cannot be made.
    pub fn from_env() -> io::Result<Self> {
        Self::from_inputs(
            std::env::var_os(SCOPE_ENV_VAR),
            std::env::var_os(ZENOH_HOME_ENV_VAR),
            home_dir(),
        )
    }

    /// [`from_env`](Self::from_env) with its three inputs given rather than
    /// read, so the whole of it -- derivation, creation, canonical form -- is
    /// testable without touching the process environment.
    fn from_inputs(
        scope: Option<std::ffi::OsString>,
        zenoh_home: Option<std::ffi::OsString>,
        user_home: Option<PathBuf>,
    ) -> io::Result<Self> {
        let root = derive_root(scope, zenoh_home, user_home);
        fs::create_dir_all(&root).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot create ${SCOPE_ENV_VAR}={}: {e}", root.display()),
            )
        })?;
        Ok(Self {
            root: canonical(&root)?,
        })
    }
}

/// Upstream's root rule as a pure function of its three inputs, so it can be
/// tested without touching the process environment: [`SCOPE_ENV_VAR`] wins;
/// otherwise [`DEFAULT_ROOT_DIR`] under the zenoh home, which is
/// [`ZENOH_HOME_ENV_VAR`] or [`DEFAULT_ZENOH_HOME_DIRNAME`] under the user's
/// home -- or, with no user home at all, that directory name relative to the
/// working directory, exactly as upstream's `zenoh_home()` falls back.
fn derive_root(
    scope: Option<std::ffi::OsString>,
    zenoh_home: Option<std::ffi::OsString>,
    user_home: Option<PathBuf>,
) -> PathBuf {
    if let Some(dir) = scope {
        return PathBuf::from(dir);
    }
    let mut home = match (zenoh_home, user_home) {
        (Some(dir), _) => PathBuf::from(dir),
        (None, Some(mut dir)) => {
            dir.push(DEFAULT_ZENOH_HOME_DIRNAME);
            dir
        }
        (None, None) => PathBuf::from(DEFAULT_ZENOH_HOME_DIRNAME),
    };
    home.push(DEFAULT_ROOT_DIR);
    home
}

/// The user's home directory, as upstream's `zenoh_home()` finds it through
/// `home::home_dir()` -- which on unix IS `std::env::home_dir()`: `HOME` when
/// set (an empty value included, which upstream then treats as a relative
/// directory), else the account's passwd entry. On windows the pinned compiler's
/// `std::env::home_dir()` reads the profile directory, as that crate's own
/// windows arm does. Calling the same function is what makes the fallback the
/// same, where reading `HOME` by hand would miss the passwd arm.
///
/// The `allow`: the call is deprecated at this workspace's MSRV and
/// un-deprecated by the pinned compiler; the `home` crate carries the same
/// allow on the same call.
#[allow(deprecated)]
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir()
}

/// `path` canonicalized as upstream canonicalizes its root (`dunce`: on
/// windows the verbatim `\\?\` prefix is dropped where the path allows it, so
/// the spelling matches what an operator and zenohd write).
fn canonical(path: &Path) -> io::Result<PathBuf> {
    dunce::canonicalize(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("invalid path for the volume root {}: {e}", path.display()),
        )
    })
}

/// Why a storage's properties could not be read. The message is upstream's
/// wording where upstream has one.
fn property_error(message: String) -> VolumeError {
    VolumeError::CreateFailed(message)
}

/// Upstream's `extract_bool`: absent is the default, a JSON boolean is itself,
/// anything else -- the STRING `"true"` included -- is refused.
fn extract_bool(
    cfg: &[(String, Json5Value)],
    key: &str,
    default: bool,
) -> Result<bool, VolumeError> {
    match cfg.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None => Ok(default),
        Some(Json5Value::Bool(b)) => Ok(*b),
        Some(_) => Err(property_error(format!(
            "Invalid value for File System Storage configuration: `{key}` must be a boolean"
        ))),
    }
}

/// Read a storage's properties off its `volume_cfg`, rule for rule as
/// upstream's `create_storage` reads them. Returns the options and the `dir`
/// the storage asked for, not yet joined onto a root.
fn read_properties(
    cfg: &[(String, Json5Value)],
) -> Result<(FilesystemOptions, PathBuf), VolumeError> {
    // Upstream's first check: the payload must be an OBJECT. An empty list is
    // wz's spelling of upstream's `Value::Null`, the bare volume id.
    if cfg.is_empty() {
        return Err(property_error(String::from(
            "fs backed volumes require volume-specific configuration",
        )));
    }
    let read_only = extract_bool(cfg, PROP_STORAGE_READ_ONLY, false)?;
    let follow_links = extract_bool(cfg, PROP_STORAGE_FOLLOW_LINK, false)?;
    let keep_mime_types = extract_bool(cfg, PROP_STORAGE_KEEP_MIME, true)?;
    let on_closure = match cfg.iter().find(|(k, _)| k == PROP_STORAGE_ON_CLOSURE) {
        None => OnClosure::DoNothing,
        Some((_, Json5Value::String(s))) if s == "delete_all" => OnClosure::DeleteAll,
        Some((_, Json5Value::String(s))) if s == "do_nothing" => OnClosure::DoNothing,
        Some((_, other)) => {
            return Err(property_error(format!(
                "Unsupported value {} for `{PROP_STORAGE_ON_CLOSURE}` property: must be either \
                 \"delete_all\" or \"do_nothing\". Default is \"do_nothing\"",
                other.to_json5_text()
            )))
        }
    };
    let dir = match cfg.iter().find(|(k, _)| k == PROP_STORAGE_DIR) {
        Some((_, Json5Value::String(dir))) => dir,
        _ => {
            return Err(property_error(format!(
                "Missing required property for File System Storage: \"{PROP_STORAGE_DIR}\""
            )))
        }
    };
    let dir_path = PathBuf::from(dir);
    if dir_path.is_absolute() {
        return Err(property_error(format!(
            "Invalid property \"{PROP_STORAGE_DIR}\"=\"{dir}\": the path must be relative"
        )));
    }
    if dir_path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(property_error(format!(
            "Invalid property \"{PROP_STORAGE_DIR}\"=\"{dir}\": the path must not contain any '..'"
        )));
    }
    Ok((
        FilesystemOptions {
            follow_links,
            keep_mime_types,
            read_only,
            on_closure,
        },
        dir_path,
    ))
}

/// Upstream's checks on the directory a storage resolved to: created when
/// absent; refused when it is not a directory or cannot be listed; and, unless
/// the storage is read-only, refused when a file cannot be written in it.
fn check_base_dir(base_dir: &Path, read_only: bool) -> Result<(), VolumeError> {
    let refuse = |why: String| {
        property_error(format!(
            "Cannot create File System Storage on \"dir\"={base_dir:?} : {why}"
        ))
    };
    if !base_dir.exists() {
        fs::create_dir_all(base_dir).map_err(|e| refuse(e.to_string()))?;
    } else if !base_dir.is_dir() {
        return Err(refuse(String::from("this is not a directory")));
    } else {
        fs::read_dir(base_dir).map_err(|e| refuse(e.to_string()))?;
    }
    if !read_only {
        // Upstream writes an anonymous temporary file here, and only into a
        // directory that already existed. This writes and removes a named one
        // in the store's own staging area, which `open` clears anyway, so a
        // probe that crashes halfway leaves nothing a listing reads -- and does
        // it for a directory it just created too, since creating one is not
        // the same as being able to write a file into it.
        let staging = base_dir.join(STAGING_DIR);
        let probe = staging.join(format!("probe.{}", std::process::id()));
        let write = || -> io::Result<()> {
            fs::create_dir_all(&staging)?;
            fs::File::create(&probe)?.write_all(b"test\n")?;
            fs::remove_file(&probe)
        };
        write().map_err(|e| {
            property_error(format!(
                "Cannot create writeable File System Storage on \"dir\"={base_dir:?} : {e}"
            ))
        })?;
    }
    Ok(())
}

impl Volume for FilesystemVolume {
    fn capability(&self) -> Capability {
        Capability {
            persistence: Persistence::Durable,
            history: History::Latest,
        }
    }

    /// Upstream's fs volume status (R2804): `{"root": …, "version": …}`, the two
    /// parameters its plugin `start` records, keys alphabetical as its
    /// `serde_json` map orders them. The root is the CANONICAL one every storage
    /// of this volume is created under; a host-given root that does not exist
    /// yet has no canonical form, and is reported as given until a storage
    /// creates it.
    fn admin_status(&self, version: &str) -> String {
        let root = canonical(&self.root).unwrap_or_else(|_| self.root.clone());
        let mut out = String::from("{\"root\":");
        wz_session_core::json::escape_into(&root.to_string_lossy(), &mut out);
        out.push_str(",\"version\":");
        wz_session_core::json::escape_into(version, &mut out);
        out.push('}');
        out
    }

    /// Upstream's `create_storage`, check for check: the properties off
    /// `volume_cfg` (see [`read_properties`]), the directory `root/<dir>`
    /// (see [`check_base_dir`]), then `dir_full_path` INSERTED into the config
    /// the storage keeps -- which is why the config is `&mut`.
    fn create_storage(
        &self,
        config: &mut StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeError> {
        let (options, dir) = read_properties(&config.volume_cfg)?;
        fs::create_dir_all(&self.root).map_err(|e| VolumeError::CreateFailed(e.to_string()))?;
        let root = canonical(&self.root).map_err(|e| VolumeError::CreateFailed(e.to_string()))?;
        let base_dir = root.join(dir);
        check_base_dir(&base_dir, options.read_only)?;
        let full = Json5Value::String(base_dir.to_string_lossy().into_owned());
        match config
            .volume_cfg
            .iter_mut()
            .find(|(k, _)| k == DIR_FULL_PATH)
        {
            Some((_, value)) => *value = full,
            None => config.volume_cfg.push((String::from(DIR_FULL_PATH), full)),
        }
        log::debug!(
            "wz-fs-storage: storage on {} will store files in {}",
            config.key_expr,
            base_dir.display()
        );
        FilesystemStorage::open_with(base_dir, options)
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
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// Off unix there is no directory `fsync` through `std`: windows refuses to
/// open a directory as a file without a flag `std` does not set, so the unix
/// arm above would fail EVERY write there (R2804, found reading this module
/// for portability, not by running it). What remains is upstream's own
/// guarantee on every platform -- it syncs nothing -- so this is never weaker
/// than the implementation it mirrors. ⚠ No lane here builds or runs this arm.
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
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

    /// A storage config naming its directory, with optional extra properties.
    fn fs_cfg(name: &str, dir: &str, extra: &[(&str, Json5Value)]) -> StorageConfig {
        let mut cfg = StorageConfig::new(name, "demo/**", "fs");
        cfg.volume_cfg.push((
            String::from(PROP_STORAGE_DIR),
            Json5Value::String(dir.into()),
        ));
        for (k, v) in extra {
            cfg.volume_cfg.push((String::from(*k), v.clone()));
        }
        cfg
    }

    fn refusal(vol: &FilesystemVolume, mut cfg: StorageConfig) -> String {
        match vol.create_storage(&mut cfg) {
            Err(VolumeError::CreateFailed(why)) => why,
            Ok(_) => panic!("a storage was created from {:?}", cfg.volume_cfg),
        }
    }

    #[test]
    fn volume_creates_durable_independent_storage_in_its_dir() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        let mut cfg = fs_cfg("demo", "sub/demo", &[]);
        {
            let mut s = vol.create_storage(&mut cfg.clone()).unwrap();
            assert_eq!(
                s.put(Some("demo/a"), vec![1, 2, 3], None, ts(10)).unwrap(),
                StorageInsertionResult::Inserted
            );
        } // drop the backend, then re-create over the same dir -> durable
        assert_eq!(
            fs::read(root.path().join("sub/demo/demo/a")).unwrap(),
            vec![1, 2, 3],
            "the storage lives at root/<dir>, not root/<name>"
        );
        let s = vol.create_storage(&mut cfg).unwrap();
        assert_eq!(
            s.get_newest(Some("demo/a")).unwrap().unwrap().payload,
            vec![1, 2, 3],
            "a storage re-created over the same dir reloads its data"
        );
        let other = vol
            .create_storage(&mut fs_cfg("other", "elsewhere", &[]))
            .unwrap();
        assert!(other.get_newest(Some("demo/a")).unwrap().is_none());
    }

    /// Upstream inserts the resolved directory into the config its storage
    /// keeps, and that is what the admin plane reports. The root is canonical,
    /// so the path is the one the sidecar keys its rows by.
    #[test]
    fn create_storage_inserts_dir_full_path_into_the_kept_config() {
        let root = tempdir().unwrap();
        // Spelled through a `..`: the path the config reports -- and the sidecar
        // keys rows by -- must be the canonical one, not the host's spelling.
        let vol = FilesystemVolume::new(root.path().join("x").join(".."));
        let mut cfg = fs_cfg("demo", "d", &[]);
        let _s = vol.create_storage(&mut cfg).unwrap();
        let want = dunce::canonicalize(root.path()).unwrap().join("d");
        assert_eq!(
            cfg.volume_cfg
                .iter()
                .find(|(k, _)| k == DIR_FULL_PATH)
                .map(|(_, v)| v.clone()),
            Some(Json5Value::String(want.to_string_lossy().into_owned()))
        );
        assert!(
            cfg.to_admin_json().contains(r#""dir_full_path":"#),
            "{}",
            cfg.to_admin_json()
        );
    }

    #[test]
    fn a_storage_without_its_payload_or_its_dir_is_refused_as_upstream_refuses() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        assert!(refusal(&vol, StorageConfig::new("s", "k/**", "fs"))
            .contains("fs backed volumes require volume-specific configuration"));
        let mut no_dir = StorageConfig::new("s", "k/**", "fs");
        no_dir.volume_cfg.push((
            String::from(PROP_STORAGE_READ_ONLY),
            Json5Value::Bool(false),
        ));
        assert!(refusal(&vol, no_dir).contains("Missing required property"));
        let mut dir_not_a_string = StorageConfig::new("s", "k/**", "fs");
        dir_not_a_string.volume_cfg.push((
            String::from(PROP_STORAGE_DIR),
            Json5Value::Number("3".into()),
        ));
        assert!(refusal(&vol, dir_not_a_string).contains("Missing required property"));
    }

    #[test]
    fn a_dir_that_would_leave_the_root_is_refused() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        assert!(refusal(&vol, fs_cfg("s", "/etc", &[])).contains("must be relative"));
        assert!(refusal(&vol, fs_cfg("s", "a/../../x", &[])).contains("must not contain any '..'"));
        assert!(!root.path().parent().unwrap().join("x").exists());
    }

    /// The reason `volume_cfg` became typed (R2802): upstream refuses a string
    /// where it takes a boolean, and the string `"true"` is the case text could
    /// not tell apart.
    #[test]
    fn a_boolean_property_given_as_a_string_is_refused() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        for key in [
            PROP_STORAGE_READ_ONLY,
            PROP_STORAGE_FOLLOW_LINK,
            PROP_STORAGE_KEEP_MIME,
        ] {
            let why = refusal(
                &vol,
                fs_cfg("s", "d", &[(key, Json5Value::String("true".into()))]),
            );
            assert!(why.contains(&format!("`{key}` must be a boolean")), "{why}");
        }
    }

    #[test]
    fn on_closure_takes_upstreams_two_values_and_refuses_any_other() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        for ok in ["delete_all", "do_nothing"] {
            let mut cfg = fs_cfg(
                ok,
                ok,
                &[(PROP_STORAGE_ON_CLOSURE, Json5Value::String(ok.into()))],
            );
            assert!(vol.create_storage(&mut cfg).is_ok(), "{ok}");
        }
        assert!(refusal(
            &vol,
            fs_cfg(
                "s",
                "d",
                &[(PROP_STORAGE_ON_CLOSURE, Json5Value::String("purge".into()))]
            )
        )
        .contains("Unsupported value"));
    }

    #[test]
    fn on_closure_delete_all_removes_the_directory_when_the_storage_closes() {
        let root = tempdir().unwrap();
        let vol = FilesystemVolume::new(root.path());
        {
            let mut s = vol
                .create_storage(&mut fs_cfg(
                    "s",
                    "gone",
                    &[(
                        PROP_STORAGE_ON_CLOSURE,
                        Json5Value::String("delete_all".into()),
                    )],
                ))
                .unwrap();
            s.put(Some("k"), vec![1], None, ts(1)).unwrap();
            assert!(root.path().join("gone/k").is_file());
        }
        assert!(
            !root.path().join("gone").exists(),
            "closure removed the directory"
        );
        // ... and the default keeps it.
        {
            let mut s = vol.create_storage(&mut fs_cfg("s", "kept", &[])).unwrap();
            s.put(Some("k"), vec![1], None, ts(1)).unwrap();
        }
        assert!(root.path().join("kept/k").is_file());
    }

    #[test]
    fn a_read_only_storage_serves_its_directory_and_refuses_every_write() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("ro")).unwrap();
        fs::write(root.path().join("ro/k"), b"there").unwrap();
        let vol = FilesystemVolume::new(root.path());
        let mut s = vol
            .create_storage(&mut fs_cfg(
                "s",
                "ro",
                &[(PROP_STORAGE_READ_ONLY, Json5Value::Bool(true))],
            ))
            .unwrap();
        assert_eq!(s.get_newest(Some("k")).unwrap().unwrap().payload, b"there");
        assert!(s.put(Some("k"), b"new".to_vec(), None, ts(1)).is_err());
        assert!(s.put(Some("fresh"), b"new".to_vec(), None, ts(1)).is_err());
        assert!(s.delete(Some("k"), ts(2)).is_err());
        assert_eq!(fs::read(root.path().join("ro/k")).unwrap(), b"there");
        assert!(!root.path().join("ro/fresh").exists());
    }

    #[test]
    fn follow_links_and_keep_mime_types_reach_the_store() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("m")).unwrap();
        fs::write(root.path().join("m/page.json"), b"{}").unwrap();
        let vol = FilesystemVolume::new(root.path());
        let s = vol
            .create_storage(&mut fs_cfg(
                "s",
                "m",
                &[(PROP_STORAGE_KEEP_MIME, Json5Value::Bool(false))],
            ))
            .unwrap();
        assert_eq!(
            s.get_newest(Some("page.json")).unwrap().unwrap().encoding,
            Some(EncodingHint::APPLICATION_OCTET_STREAM),
            "keep_mime_types false reached the store"
        );
        drop(s);
        let s = vol.create_storage(&mut fs_cfg("s", "m", &[])).unwrap();
        assert_eq!(
            s.get_newest(Some("page.json")).unwrap().unwrap().encoding,
            Some(EncodingHint::APPLICATION_JSON),
            "and its default is upstream's true"
        );
    }

    #[test]
    fn the_root_is_derived_as_upstreams_plugin_derives_it() {
        use std::ffi::OsString;
        let home = PathBuf::from("/home/u");
        // The scope variable wins over everything.
        assert_eq!(
            derive_root(
                Some(OsString::from("/srv/fs")),
                Some(OsString::from("/z")),
                Some(home.clone())
            ),
            PathBuf::from("/srv/fs")
        );
        // Else the zenoh home, then the default directory under it.
        assert_eq!(
            derive_root(None, Some(OsString::from("/z")), Some(home.clone())),
            PathBuf::from("/z/zenoh_backend_fs")
        );
        assert_eq!(
            derive_root(None, None, Some(home)),
            PathBuf::from("/home/u/.zenoh/zenoh_backend_fs")
        );
        // No user home at all: the zenoh home is relative, as upstream's is.
        assert_eq!(
            derive_root(None, None, None),
            PathBuf::from(".zenoh/zenoh_backend_fs")
        );
    }

    /// The derived root is CREATED and CANONICALIZED, as upstream's plugin does
    /// before it hands the root to any storage -- the sidecar keys its rows by
    /// full path, so the spelling is part of the format.
    #[test]
    fn from_env_creates_and_canonicalizes_the_derived_root() {
        let home = tempdir().unwrap();
        let spelled = home.path().join("x/../z");
        let vol = FilesystemVolume::from_inputs(
            None,
            Some(spelled.into_os_string()),
            Some(PathBuf::from("/nonexistent")),
        )
        .unwrap();
        let want = dunce::canonicalize(home.path())
            .unwrap()
            .join("z")
            .join(DEFAULT_ROOT_DIR);
        assert!(want.is_dir(), "the root was created");
        assert_eq!(vol.root, want, "and held in its canonical spelling");
    }

    /// R2804 — the volume's admin body is upstream's fs volume status: the
    /// canonical root and the version, keys in `serde_json`'s map order. The
    /// root is given through a `..` over a directory that exists, so a body
    /// that echoed the host's spelling could not pass.
    #[test]
    fn the_volume_reports_upstreams_root_and_version() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("x")).unwrap();
        let vol = FilesystemVolume::new(root.path().join("x").join(".."));
        let mut want = String::from("{\"root\":");
        wz_session_core::json::escape_into(
            &dunce::canonicalize(root.path()).unwrap().to_string_lossy(),
            &mut want,
        );
        want.push_str(",\"version\":\"1.2.3\"}");
        assert_eq!(vol.admin_status("1.2.3"), want);
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 — the host<->VOLUME C ABI both sides of a `dlopen` boundary link
//! independently.
//!
//! ## Why this exists, given R311y256 deprecated the atom it serves
//!
//! R311y256 deprecated `storage-mgr-dynamic-volume-loading` as OBVIATED —
//! correctly, at the time: wz composed every volume at BUILD time through cargo
//! features and `cfg`, so there was no runtime loader for a volume to be loaded
//! by. The same round wrote the condition into the reason instead of dropping it:
//! *"if `plugin-dynamic-loading` is ever built, this returns with it."*
//! R311y492 built `plugin-dynamic-loading`, so R311y496 moved this atom back to
//! `reserved` and Layer A5 has printed it as OPEN on every run since. This crate
//! is the first half of it returning.
//!
//! ## The contract
//!
//! A volume is a `cdylib` exporting ONE symbol, [`ENTRY_SYMBOL`], of type
//! [`EntryFn`]. It returns a pointer to a [`VolumeEntry`] with static lifetime,
//! carrying the ABI numbers, two layout fingerprints, and a [`VolumeVTable`].
//!
//! A volume is a FACTORY: [`VolumeVTable::create_store`] makes one store per
//! hosted storage, and each store is then put to, deleted from, enumerated and
//! finally dropped through the same vtable. That mirrors the in-tree
//! `Volume` / `StorageBackend` split exactly, which is what lets the host wrap a
//! loaded volume in the ordinary seam rather than special-casing it upward.
//!
//! ## Two layout fingerprints, not one
//!
//! `wz-plugin-abi` gates on the vtable's size and alignment alone, and that is
//! sufficient there: every argument it passes across the boundary is a
//! `*const c_char` or a scalar. This ABI passes a STRUCT BY POINTER
//! ([`StoredEntry`]), so that struct's layout is part of the contract too — a
//! volume rebuilt against a stale header would agree on the vtable and disagree
//! on the record it is handed, which is the failure the version numbers cannot
//! see. [`VolumeEntry::compatibility`] therefore checks both.
//!
//! ## What the gate cannot check
//!
//! That the function pointers do what they say. Nothing at a `dlopen` boundary
//! can. The gate turns the failures it CAN see into a refusal instead of a jump
//! into a mis-shaped struct, and that bound is stated rather than implied —
//! zenoh's `StructVersion` (`compatibility.rs`) hashes field layout and has the
//! same limit.
//!
//! ## Threading, stated because the host relies on it
//!
//! A [`StoreHandle`] is created on one thread and may be USED from another, but
//! never from two at once: the host owns each handle behind a `&mut` for
//! mutations and a `&` for reads, exactly as it owns an in-tree backend. A volume
//! that parks a store's state in thread-local storage would break this and is out
//! of contract. Nothing here can enforce that, which is why it is written down.

#![no_std]

use core::ffi::{c_char, c_int, c_void};

/// The symbol a volume `cdylib` must export, NUL-terminated for `dlsym`.
///
/// Distinct from `wz_plugin_abi::ENTRY_SYMBOL` on purpose: one shared object may
/// legitimately be BOTH a plugin and a volume, and a single symbol name would
/// make that unrepresentable while silently letting the wrong loader resolve the
/// wrong vtable.
pub const ENTRY_SYMBOL: &[u8] = b"wz_volume_entry\0";

/// The ABI major this host speaks. Bumped when a vtable field changes MEANING.
pub const ABI_MAJOR: u32 = 1;
/// The ABI minor this host speaks. Bumped when a vtable field is APPENDED.
pub const ABI_MINOR: u32 = 0;

/// The signature of [`ENTRY_SYMBOL`].
///
/// # Safety
/// The returned pointer must be non-null and valid for the lifetime of the
/// loaded library, and must point at a [`VolumeEntry`] whose `vtable` is likewise
/// valid for that lifetime. A `static` in the volume satisfies both.
pub type EntryFn = unsafe extern "C" fn() -> *const VolumeEntry;

/// Success for the `c_int`-returning vtable calls.
pub const OK: c_int = 0;
/// Generic failure. Any non-zero value that is not an insertion result means
/// failure; this is the one a volume should use when it has nothing specific.
pub const ERR: c_int = -1;

/// A mutation created a new key — mirrors `StorageInsertionResult::Inserted`.
pub const INSERTED: c_int = 1;
/// A mutation overwrote an existing key — `StorageInsertionResult::Replaced`.
pub const REPLACED: c_int = 2;
/// A key was removed — `StorageInsertionResult::Deleted`.
pub const DELETED: c_int = 3;

/// No post-crash guarantee — a cache. Mirrors `Persistence::Volatile`.
pub const PERSISTENCE_VOLATILE: u32 = 0;
/// Survives a restart with values and metadata. `Persistence::Durable`.
pub const PERSISTENCE_DURABLE: u32 = 1;

/// One value per key. Mirrors `History::Latest`.
pub const HISTORY_LATEST: u32 = 0;
/// Every version per key. Mirrors `History::All`.
pub const HISTORY_ALL: u32 = 1;

/// An opaque store instance, created by [`VolumeVTable::create_store`] and
/// released by [`VolumeVTable::store_drop`]. The host never dereferences it.
pub type StoreHandle = *mut c_void;

/// A volume's guarantees — the `repr(C)` projection of the in-tree `Capability`.
///
/// Returned BY VALUE (two `u32`s) rather than through an out-pointer: there is no
/// failure mode to report, and a getter that cannot fail should not be shaped
/// like one.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeCapability {
    /// [`PERSISTENCE_VOLATILE`] or [`PERSISTENCE_DURABLE`]. An unrecognised
    /// value is read by the host as Volatile — the conservative direction, since
    /// claiming durability wrongly is what loses data.
    pub persistence: u32,
    /// [`HISTORY_LATEST`] or [`HISTORY_ALL`]. An unrecognised value is read as
    /// Latest.
    pub history: u32,
}

/// The declarative config a store is created from — the `repr(C)` borrowed view
/// of the in-tree `StorageConfig` fields a VOLUME is entitled to see.
///
/// `key_expr` and `strip_prefix` are included because a durable volume needs
/// them to lay out its own storage (a directory per mount, say), NOT so it can
/// apply them: the strip/restore and completeness transforms belong to the
/// storage service above the backend, exactly as in the in-tree seam and in
/// zenoh. A volume that stripped keys itself would double-strip.
#[repr(C)]
#[derive(Debug)]
pub struct StoreConfig {
    /// The storage's manager-unique name, NUL-terminated UTF-8.
    pub name: *const c_char,
    /// The keyexpr the storage is mounted on, NUL-terminated UTF-8.
    pub key_expr: *const c_char,
    /// The configured strip prefix, or null when none is configured.
    pub strip_prefix: *const c_char,
}

/// One stored value crossing the boundary in either direction.
///
/// The SAME record shape carries a `put` argument, a `delete` argument (payload
/// null, length zero — a delete is versioned but valueless) and an enumeration
/// result. One record rather than three keeps the vtable narrow and means the
/// layout gate covers every crossing.
///
/// Every pointer is borrowed for the duration of the call ONLY. Neither side
/// frees the other's memory, ever: on the way in the host owns the buffers, and
/// on the way out the volume does. That is why enumeration is a callback
/// ([`EntrySink`]) instead of a returned array — an array would have to be
/// allocated by one side and freed by the other, which is the classic C-ABI
/// ownership bug this shape does not have.
#[repr(C)]
#[derive(Debug)]
pub struct StoredEntry {
    /// The key within the store, NUL-terminated UTF-8, or NULL for the
    /// mount-root slot (the in-tree `Option<&str>` key's `None`, which is what a
    /// strip-configured storage stores its exact-prefix-match value under).
    pub key: *const c_char,
    /// The payload bytes. May be null iff `payload_len` is 0.
    pub payload: *const u8,
    /// The payload length in bytes.
    pub payload_len: usize,
    /// Non-zero when the encoding fields carry a value. A sample published
    /// without an encoding has none, which is distinct from an encoding whose
    /// packed id happens to be 0.
    pub has_encoding: c_int,
    /// The VLE-packed encoding id word (`EncodingHint::packed_id`). Meaningful
    /// only when `has_encoding` is non-zero.
    pub encoding_packed_id: u32,
    /// The encoding's schema string, NUL-terminated UTF-8, or null when absent.
    pub encoding_schema: *const c_char,
    /// The NTP64 time word of the version timestamp.
    pub ts_time: u64,
    /// The timestamp's zid prefix bytes. May be null iff `ts_zid_len` is 0.
    pub ts_zid: *const u8,
    /// The zid prefix length in bytes.
    pub ts_zid_len: usize,
}

/// The callback [`VolumeVTable::store_entries`] reports each stored value
/// through.
///
/// # Safety
/// The volume calls this once per stored entry, with `ctx` passed through
/// verbatim and `entry` valid for the duration of that one call. The host's
/// implementation must not unwind across the boundary.
pub type EntrySink = unsafe extern "C" fn(ctx: *mut c_void, entry: *const StoredEntry);

/// A volume's exported descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct VolumeEntry {
    /// The ABI major the volume was built against.
    pub abi_major: u32,
    /// The ABI minor the volume was built against.
    pub abi_minor: u32,
    /// `size_of::<VolumeVTable>()` as the VOLUME saw it.
    pub vtable_size: u32,
    /// `align_of::<VolumeVTable>()` as the VOLUME saw it.
    pub vtable_align: u32,
    /// `size_of::<StoredEntry>()` as the VOLUME saw it. Checked separately from
    /// the vtable because this record crosses the boundary BY POINTER — see the
    /// module doc.
    pub entry_size: u32,
    /// `align_of::<StoredEntry>()` as the VOLUME saw it.
    pub entry_align: u32,
    /// The call table. Valid only once [`Self::compatibility`] returns
    /// [`Compatibility::Ok`] — reading through it otherwise is exactly the
    /// mis-shaped-struct jump the gate exists to prevent.
    pub vtable: *const VolumeVTable,
}

// SAFETY: `VolumeEntry` is an immutable descriptor. Its only non-`Sync` field is
// the `vtable` POINTER, and a pointer value is as shareable as the `u32`s beside
// it — reading it from several threads races on nothing. Dereferencing it is
// `unsafe` regardless and is governed by the contract on [`EntryFn`], which
// requires the pointee to be valid for the loaded library's lifetime.
//
// The impl lives here rather than in each volume because it is a property of this
// type: a volume's entry is naturally a `static`, a `static` needs `Sync`, and
// leaving this out would push every volume author into writing their own
// `unsafe impl` for a reason none of them should have to re-derive.
unsafe impl Sync for VolumeEntry {}

/// The verdict of the volume ABI gate.
///
/// A rejection carries WHICH check failed and both operands, because
/// "incompatible" with no numbers is the diagnostic that sends the next reader
/// into the loader's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// Safe to read `vtable` through.
    Ok,
    /// `abi_major` differs; the vtable's meaning is not shared.
    MajorMismatch { host: u32, plugin: u32 },
    /// The volume wants a newer host than this one.
    MinorTooNew { host: u32, plugin: u32 },
    /// Same declared ABI, different vtable shape — a stale rebuild.
    VTableLayoutMismatch {
        host_size: u32,
        plugin_size: u32,
        host_align: u32,
        plugin_align: u32,
    },
    /// Same declared ABI and vtable, different [`StoredEntry`] shape. The check
    /// `wz-plugin-abi` has no need of, because it passes no struct by pointer.
    EntryLayoutMismatch {
        host_size: u32,
        plugin_size: u32,
        host_align: u32,
        plugin_align: u32,
    },
}

impl Compatibility {
    /// `true` only for [`Compatibility::Ok`].
    pub fn is_ok(self) -> bool {
        matches!(self, Compatibility::Ok)
    }
}

impl VolumeEntry {
    /// Build the descriptor for a vtable, filling all four layout fields from the
    /// VOLUME's own view of the types.
    ///
    /// Volumes should use this rather than filling the struct by hand: the whole
    /// value of the layout check is that the numbers come from `size_of` /
    /// `align_of` at each side's compile time, and a hand-written constant would
    /// silently keep matching after the struct changed.
    pub const fn new(vtable: *const VolumeVTable) -> Self {
        Self {
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
            vtable_size: core::mem::size_of::<VolumeVTable>() as u32,
            vtable_align: core::mem::align_of::<VolumeVTable>() as u32,
            entry_size: core::mem::size_of::<StoredEntry>() as u32,
            entry_align: core::mem::align_of::<StoredEntry>() as u32,
            vtable,
        }
    }

    /// Run the ABI gate against THIS host's expectations.
    ///
    /// Pure, total, and callable before any volume code has run beyond the entry
    /// function's `return &STATIC` — which is the point of specifying the entry
    /// function to do nothing else.
    pub fn compatibility(&self) -> Compatibility {
        if self.abi_major != ABI_MAJOR {
            return Compatibility::MajorMismatch {
                host: ABI_MAJOR,
                plugin: self.abi_major,
            };
        }
        if self.abi_minor > ABI_MINOR {
            return Compatibility::MinorTooNew {
                host: ABI_MINOR,
                plugin: self.abi_minor,
            };
        }
        let vt_size = core::mem::size_of::<VolumeVTable>() as u32;
        let vt_align = core::mem::align_of::<VolumeVTable>() as u32;
        if self.vtable_size != vt_size || self.vtable_align != vt_align {
            return Compatibility::VTableLayoutMismatch {
                host_size: vt_size,
                plugin_size: self.vtable_size,
                host_align: vt_align,
                plugin_align: self.vtable_align,
            };
        }
        let e_size = core::mem::size_of::<StoredEntry>() as u32;
        let e_align = core::mem::align_of::<StoredEntry>() as u32;
        if self.entry_size != e_size || self.entry_align != e_align {
            return Compatibility::EntryLayoutMismatch {
                host_size: e_size,
                plugin_size: self.entry_size,
                host_align: e_align,
                plugin_align: self.entry_align,
            };
        }
        Compatibility::Ok
    }
}

/// A volume's call table, expressed as C function pointers rather than a Rust
/// trait for the reason the module doc gives.
///
/// The three metadata getters return NUL-terminated UTF-8 valid for the loaded
/// library's lifetime; the host copies them into its registry rather than holding
/// the pointers, so a volume may return `static` strings.
#[repr(C)]
#[derive(Debug)]
pub struct VolumeVTable {
    /// Registry key — the `volume_id` a storage config names to be hosted here.
    pub id: unsafe extern "C" fn() -> *const c_char,
    /// Human name.
    pub name: unsafe extern "C" fn() -> *const c_char,
    /// Volume version string.
    pub version: unsafe extern "C" fn() -> *const c_char,
    /// This volume's guarantees. Read AFTER [`Self::configure`], because a
    /// volume's persistence may depend on the configuration it was given (a
    /// file-backed volume with nowhere to write is not durable).
    pub capability: unsafe extern "C" fn() -> VolumeCapability,
    /// Hand the volume its operator configuration once, before any store is
    /// created. `config` is a NUL-terminated string, or null for none; its
    /// meaning belongs to the volume. Returns [`OK`], or non-zero to refuse — in
    /// which case the host loads NO store from this volume.
    ///
    /// Separate from the entry function so a host can interrogate a `.so`'s
    /// identity and ABI without letting it act, and separate from
    /// [`Self::create_store`] because configuration is per-volume while a store
    /// is per-storage.
    pub configure: unsafe extern "C" fn(config: *const c_char) -> c_int,
    /// Create one store for `config`, or return null if the volume cannot. The
    /// returned handle is opaque to the host and is released by
    /// [`Self::store_drop`].
    pub create_store: unsafe extern "C" fn(config: *const StoreConfig) -> StoreHandle,
    /// Store `entry`'s value under `entry.key`, versioned by its timestamp.
    /// Returns [`INSERTED`], [`REPLACED`], or [`ERR`].
    ///
    /// A volume does NOT compare timestamps: newer-wins is the storage service's
    /// decision above the backend, exactly as in zenoh, so an older `put` still
    /// replaces here.
    pub store_put: unsafe extern "C" fn(handle: StoreHandle, entry: *const StoredEntry) -> c_int,
    /// Remove `entry.key`. Returns [`DELETED`] even for an absent key (the
    /// in-tree seam's contract), or [`ERR`]. Only the key and timestamp fields
    /// are meaningful.
    pub store_delete: unsafe extern "C" fn(handle: StoreHandle, entry: *const StoredEntry) -> c_int,
    /// Report every stored value through `sink`, passing `ctx` back verbatim.
    /// Returns [`OK`] or [`ERR`].
    ///
    /// This is the call that makes durability observable: the host rebuilds its
    /// read mirror from it when a store is created, so a value a previous process
    /// put is served by this one only if the volume reports it here.
    pub store_entries:
        unsafe extern "C" fn(handle: StoreHandle, sink: EntrySink, ctx: *mut c_void) -> c_int,
    /// Release a store. Called exactly once per successful
    /// [`Self::create_store`], and never with a null handle.
    pub store_drop: unsafe extern "C" fn(handle: StoreHandle),
}

#[cfg(test)]
mod tests {
    use super::*;

    // The vtable is never dereferenced by these tests: the gate is pure
    // arithmetic over the descriptor, which is exactly what makes it callable
    // before any volume code runs.
    fn entry(major: u32, minor: u32) -> VolumeEntry {
        let mut e = VolumeEntry::new(core::ptr::null());
        e.abi_major = major;
        e.abi_minor = minor;
        e
    }

    #[test]
    fn a_matching_volume_passes() {
        assert_eq!(
            entry(ABI_MAJOR, ABI_MINOR).compatibility(),
            Compatibility::Ok
        );
    }

    #[test]
    fn a_major_bump_is_rejected_in_both_directions() {
        assert!(matches!(
            entry(ABI_MAJOR + 1, ABI_MINOR).compatibility(),
            Compatibility::MajorMismatch { .. }
        ));
        assert!(matches!(
            entry(ABI_MAJOR.wrapping_sub(1), ABI_MINOR).compatibility(),
            Compatibility::MajorMismatch { .. }
        ));
    }

    #[test]
    fn an_older_minor_is_accepted_and_a_newer_one_is_not() {
        // The asymmetry IS the rule: a host may know fields the volume never
        // fills, but a volume expecting a newer host may reach for one that is
        // not there.
        assert_eq!(
            entry(ABI_MAJOR, ABI_MINOR).compatibility(),
            Compatibility::Ok
        );
        assert!(matches!(
            entry(ABI_MAJOR, ABI_MINOR + 1).compatibility(),
            Compatibility::MinorTooNew { .. }
        ));
    }

    #[test]
    fn a_stale_vtable_rebuild_is_caught_at_the_same_abi() {
        let mut e = entry(ABI_MAJOR, ABI_MINOR);
        e.vtable_size += 8;
        assert!(matches!(
            e.compatibility(),
            Compatibility::VTableLayoutMismatch { .. }
        ));

        let mut e = entry(ABI_MAJOR, ABI_MINOR);
        e.vtable_align *= 2;
        assert!(matches!(
            e.compatibility(),
            Compatibility::VTableLayoutMismatch { .. }
        ));
    }

    #[test]
    fn a_stale_stored_entry_rebuild_is_caught_independently_of_the_vtable() {
        // The check wz-plugin-abi does not need and this ABI does: `StoredEntry`
        // crosses the boundary by POINTER, so a volume that agrees on the vtable
        // and disagrees on the record would read the host's bytes at the wrong
        // offsets. The vtable fields are left correct here on purpose, so this
        // can only be the entry check firing.
        let mut e = entry(ABI_MAJOR, ABI_MINOR);
        e.entry_size += 8;
        assert!(matches!(
            e.compatibility(),
            Compatibility::EntryLayoutMismatch { .. }
        ));

        let mut e = entry(ABI_MAJOR, ABI_MINOR);
        e.entry_align *= 2;
        assert!(matches!(
            e.compatibility(),
            Compatibility::EntryLayoutMismatch { .. }
        ));
    }

    #[test]
    fn new_fills_all_four_layout_fields_from_this_compilation_unit() {
        let e = VolumeEntry::new(core::ptr::null());
        assert_eq!(e.vtable_size, core::mem::size_of::<VolumeVTable>() as u32);
        assert_eq!(e.vtable_align, core::mem::align_of::<VolumeVTable>() as u32);
        assert_eq!(e.entry_size, core::mem::size_of::<StoredEntry>() as u32);
        assert_eq!(e.entry_align, core::mem::align_of::<StoredEntry>() as u32);
        assert!(e.compatibility().is_ok());
    }

    #[test]
    fn the_entry_symbol_differs_from_the_plugin_abis() {
        // Not a tautology check: one shared object may be both a plugin and a
        // volume, and a shared symbol name would let the wrong loader resolve the
        // wrong vtable and pass its own gate while doing it.
        assert_eq!(ENTRY_SYMBOL, b"wz_volume_entry\0");
        assert_ne!(ENTRY_SYMBOL, b"wz_plugin_entry\0");
    }

    #[test]
    fn the_insertion_result_codes_are_distinct_and_non_error() {
        // ERR must not collide with any result the host reads as success, or a
        // failed put would be recorded as a successful one.
        for code in [INSERTED, REPLACED, DELETED] {
            assert_ne!(code, ERR);
            assert_ne!(code, OK);
        }
        assert_ne!(INSERTED, REPLACED);
        assert_ne!(REPLACED, DELETED);
    }
}

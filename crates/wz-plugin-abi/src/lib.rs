// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.22 — the host<->plugin C ABI both sides of a `dlopen` boundary link
//! independently.
//!
//! ## Why this exists at all, given R311y256 deprecated four of the five atoms
//!
//! R311y256 deprecated `plugin-manager`, `-host-trait`, `-lifecycle` and
//! `-abi-compat` on a correct reading: each exists ONLY to serve dynamic
//! loading, and wz composed every subsystem statically, so there was no runtime
//! registry, no uniform start seam, no Declared->Loaded step and no cross-binary
//! ABI to gate. The same round kept `plugin-dynamic-loading` as `reserved` and
//! wrote down what would happen if it were ever built: *"the other four exist
//! only to SERVE dynamic loading, so if this is ever built they return with
//! it."* This crate is the first of them returning.
//!
//! ## The contract
//!
//! A plugin is a `cdylib` exporting ONE symbol, [`ENTRY_SYMBOL`], of type
//! [`EntryFn`]. It returns a pointer to a [`PluginEntry`] with static lifetime,
//! carrying the ABI numbers and a [`PluginVTable`].
//!
//! Everything is `repr(C)` and `no_std`, and that is not conservatism. The two
//! sides are separate compilation units that need not share a rustc version, so
//! a Rust-ABI type crossing this boundary is undefined behaviour waiting for a
//! toolchain bump. A C plugin can implement this contract with no Rust at all.
//!
//! ## What the compatibility gate actually checks, and what it cannot
//!
//! [`PluginEntry::compatibility`] is the `plugin-abi-compat` atom. It compares
//! three things the host knows and the plugin declares:
//!
//! 1. `abi_major` — must be EQUAL. A major bump means the vtable's meaning
//!    changed, and no amount of size agreement makes that safe.
//! 2. `abi_minor` — the plugin's must be `<=` the host's. A host may know more
//!    fields than the plugin fills; a plugin that expects a NEWER host is
//!    rejected, because the field it wants may not exist here.
//! 3. `vtable_size` / `vtable_align` — must match the host's own
//!    `size_of`/`align_of`. This is the check that catches the case the version
//!    numbers cannot: the same declared ABI compiled against a struct that
//!    changed underneath, which is precisely what an out-of-tree plugin rebuilt
//!    against a stale header looks like.
//!
//! It CANNOT check that the function pointers do what they say. Nothing at a
//! `dlopen` boundary can. The gate's job is to turn the failures it can see into
//! a refusal instead of a jump into a mis-shaped struct, and that bound is
//! stated here rather than implied — zenoh's `StructVersion` (`compatibility.rs`)
//! hashes field layout and has the same limit.

#![no_std]

use core::ffi::{c_char, c_int};

/// The symbol a plugin `cdylib` must export, NUL-terminated for `dlsym`.
///
/// Deliberately not `wz_plugin_init` or similar: it returns a descriptor and
/// runs no initialisation, so a host can interrogate compatibility WITHOUT
/// letting the plugin execute anything beyond returning a pointer. Starting is a
/// separate, explicit call ([`PluginVTable::start`]) that only happens after the
/// gate passes.
pub const ENTRY_SYMBOL: &[u8] = b"wz_plugin_entry\0";

/// The ABI major this host speaks. Bumped when a vtable field changes MEANING.
pub const ABI_MAJOR: u32 = 1;
/// The ABI minor this host speaks. Bumped when a vtable field is APPENDED.
pub const ABI_MINOR: u32 = 0;

/// The signature of [`ENTRY_SYMBOL`].
///
/// # Safety
/// The returned pointer must be non-null and valid for the lifetime of the
/// loaded library, and must point at a [`PluginEntry`] whose `vtable` is
/// likewise valid for that lifetime. A `static` in the plugin satisfies both.
pub type EntryFn = unsafe extern "C" fn() -> *const PluginEntry;

/// Return codes for [`PluginVTable::start`] / [`PluginVTable::stop`].
pub const OK: c_int = 0;
/// The plugin refused to start or stop. Any non-zero value means failure; this
/// is the one a plugin should use when it has nothing more specific.
pub const ERR: c_int = -1;

/// A plugin's exported descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct PluginEntry {
    /// The ABI major the plugin was built against.
    pub abi_major: u32,
    /// The ABI minor the plugin was built against.
    pub abi_minor: u32,
    /// `size_of::<PluginVTable>()` as the PLUGIN saw it.
    pub vtable_size: u32,
    /// `align_of::<PluginVTable>()` as the PLUGIN saw it.
    pub vtable_align: u32,
    /// The call table. Valid only once [`Self::compatibility`] returns
    /// [`Compatibility::Ok`] — reading through it otherwise is exactly the
    /// mis-shaped-struct jump the gate exists to prevent.
    pub vtable: *const PluginVTable,
}

// SAFETY: `PluginEntry` is an immutable descriptor. Its only non-`Sync` field is
// the `vtable` POINTER, and a pointer value is as shareable as the `u32`s beside
// it — reading it from several threads races on nothing. Dereferencing it is
// `unsafe` regardless and is governed by the contract on [`EntryFn`], which
// requires the pointee to be valid for the loaded library's lifetime.
//
// The impl lives here rather than in each plugin because it is a property of
// this type, and leaving it out would push every plugin author into writing
// their own `unsafe impl` — an `unsafe` that is correct for the reason above and
// that none of them should have to re-derive. A plugin's entry is naturally a
// `static`, and a `static` needs `Sync`.
unsafe impl Sync for PluginEntry {}

/// The verdict of the `plugin-abi-compat` gate.
///
/// A rejection carries WHICH check failed and both numbers, because "plugin
/// incompatible" with no operand is the diagnostic that sends someone to read
/// the loader source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// Safe to read `vtable` through.
    Ok,
    /// `abi_major` differs; the vtable's meaning is not shared.
    MajorMismatch { host: u32, plugin: u32 },
    /// The plugin wants a newer host than this one.
    MinorTooNew { host: u32, plugin: u32 },
    /// Same declared ABI, different struct shape — a stale rebuild.
    LayoutMismatch {
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

impl PluginEntry {
    /// Build the descriptor for a vtable, filling the layout fields from the
    /// PLUGIN's own view of [`PluginVTable`].
    ///
    /// Plugins should use this rather than filling the struct by hand: the whole
    /// value of the layout check is that both numbers come from `size_of` /
    /// `align_of` at each side's compile time, and a hand-written constant would
    /// silently keep matching after the struct changed.
    pub const fn new(vtable: *const PluginVTable) -> Self {
        Self {
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
            vtable_size: core::mem::size_of::<PluginVTable>() as u32,
            vtable_align: core::mem::align_of::<PluginVTable>() as u32,
            vtable,
        }
    }

    /// Run the `plugin-abi-compat` gate against THIS host's expectations.
    ///
    /// Pure, total, and callable before any plugin code has run — which is the
    /// point: the only plugin code executed before this verdict is the entry
    /// function's `return &STATIC`.
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
        let host_size = core::mem::size_of::<PluginVTable>() as u32;
        let host_align = core::mem::align_of::<PluginVTable>() as u32;
        if self.vtable_size != host_size || self.vtable_align != host_align {
            return Compatibility::LayoutMismatch {
                host_size,
                plugin_size: self.vtable_size,
                host_align,
                plugin_align: self.vtable_align,
            };
        }
        Compatibility::Ok
    }
}

/// The plugin's call table — the `plugin-host-trait` atom, expressed as C
/// function pointers rather than a Rust trait for the reason the module doc
/// gives.
///
/// The three metadata getters return NUL-terminated UTF-8 valid for the loaded
/// library's lifetime; the host copies them into its registry rather than
/// holding the pointers, so a plugin may return `static` strings.
#[repr(C)]
#[derive(Debug)]
pub struct PluginVTable {
    /// Registry key — the admin-space reply-key leaf.
    pub id: unsafe extern "C" fn() -> *const c_char,
    /// Human name.
    pub name: unsafe extern "C" fn() -> *const c_char,
    /// Plugin version string.
    pub version: unsafe extern "C" fn() -> *const c_char,
    /// Activate. `config` is a NUL-terminated JSON object, or null for none.
    /// Returns [`OK`], or non-zero to refuse (the host leaves the plugin
    /// `Loaded` and does NOT call [`Self::stop`]).
    pub start: unsafe extern "C" fn(config: *const c_char) -> c_int,
    /// Deactivate. Called only after a [`Self::start`] that returned [`OK`].
    pub stop: unsafe extern "C" fn() -> c_int,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A vtable is never dereferenced by these tests; the gate is pure arithmetic
    // over the descriptor, which is exactly what makes it callable before any
    // plugin code runs.
    fn entry(major: u32, minor: u32, size: u32, align: u32) -> PluginEntry {
        PluginEntry {
            abi_major: major,
            abi_minor: minor,
            vtable_size: size,
            vtable_align: align,
            vtable: core::ptr::null(),
        }
    }

    fn host_size() -> u32 {
        core::mem::size_of::<PluginVTable>() as u32
    }
    fn host_align() -> u32 {
        core::mem::align_of::<PluginVTable>() as u32
    }

    #[test]
    fn a_matching_plugin_passes() {
        assert_eq!(
            entry(ABI_MAJOR, ABI_MINOR, host_size(), host_align()).compatibility(),
            Compatibility::Ok
        );
    }

    #[test]
    fn a_major_bump_is_rejected_in_both_directions() {
        assert!(matches!(
            entry(ABI_MAJOR + 1, ABI_MINOR, host_size(), host_align()).compatibility(),
            Compatibility::MajorMismatch { .. }
        ));
        assert!(matches!(
            entry(
                ABI_MAJOR.wrapping_sub(1),
                ABI_MINOR,
                host_size(),
                host_align()
            )
            .compatibility(),
            Compatibility::MajorMismatch { .. }
        ));
    }

    #[test]
    fn an_older_minor_is_accepted_and_a_newer_one_is_not() {
        // The asymmetry IS the rule: a host may know fields the plugin never
        // fills, but a plugin expecting a newer host may reach for one that is
        // not there.
        assert_eq!(
            entry(ABI_MAJOR, ABI_MINOR, host_size(), host_align()).compatibility(),
            Compatibility::Ok
        );
        assert!(matches!(
            entry(ABI_MAJOR, ABI_MINOR + 1, host_size(), host_align()).compatibility(),
            Compatibility::MinorTooNew { .. }
        ));
    }

    #[test]
    fn a_stale_rebuild_is_caught_by_layout_even_at_the_same_abi() {
        // The check the version numbers cannot make: same declared ABI, struct
        // changed underneath.
        assert!(matches!(
            entry(ABI_MAJOR, ABI_MINOR, host_size() + 8, host_align()).compatibility(),
            Compatibility::LayoutMismatch { .. }
        ));
        assert!(matches!(
            entry(ABI_MAJOR, ABI_MINOR, host_size(), host_align() * 2).compatibility(),
            Compatibility::LayoutMismatch { .. }
        ));
    }

    #[test]
    fn new_fills_layout_from_this_compilation_unit() {
        let e = PluginEntry::new(core::ptr::null());
        assert_eq!(e.vtable_size, host_size());
        assert_eq!(e.vtable_align, host_align());
        assert!(e.compatibility().is_ok());
    }
}

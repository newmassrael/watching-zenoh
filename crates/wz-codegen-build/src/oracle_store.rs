// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The machine's oracle store, and where in it the `sce-codegen` of a source
//! state is kept.
//!
//! A build of `sce-codegen` in one checkout served that checkout alone, so a
//! new worktree, or a copy a build machine made of the tree, built it again
//! from nothing at a pin another tree of the same machine had built already:
//! one core for most of an hour. `scripts/build-sce.sh` also keeps what it
//! builds in the store `scripts/lib/oracle_store.py` keeps zenohd in, under a
//! name made of everything that decides the binary, and both doors look there
//! first ("The store" in `scripts/lib/sce-codegen-oracle.sh`). Each function
//! here names its shell twin; the two must name the same path, and
//! `tests/provenance.rs` runs the shell to hold them to it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The variable that names the machine's oracle store. Unset, empty or
/// relative, the store is `$XDG_CACHE_HOME/watching-zenoh/oracles`, and with
/// that passed over too, `$HOME/.cache/watching-zenoh/oracles`.
pub const ORACLE_STORE_ENV: &str = "WZ_ORACLE_STORE";

/// The script, relative to the checkout, whose text decides what a build of the
/// SCE checkout makes: its cargo command, the features, the toolchain rule. Its
/// digest is part of a store entry's name, so an edited recipe is another entry.
pub const SCE_CODEGEN_RECIPE: &str = "scripts/build-sce.sh";

/// [`oracle_store_root`] with its inputs explicit: the values of
/// [`ORACLE_STORE_ENV`], `XDG_CACHE_HOME` and `HOME`, in that order. A value
/// that is absent, empty or relative is passed over, as the XDG rule says of its
/// variables: a relative one names another place from every directory a
/// consumer runs in. `None` when none is left. The shell reading is
/// `sce_codegen_store_root`; `store_root` in `scripts/lib/oracle_store.py`
/// reads the same three in the same order.
pub fn oracle_store_root_in(
    explicit: Option<&OsStr>,
    xdg_cache_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let absolute = |v: Option<&OsStr>| {
        v.map(Path::new)
            .filter(|p| p.is_absolute())
            .map(Path::to_path_buf)
    };
    if let Some(store) = absolute(explicit) {
        return Some(store);
    }
    let cache = absolute(xdg_cache_home).or_else(|| absolute(home).map(|h| h.join(".cache")))?;
    Some(cache.join("watching-zenoh").join("oracles"))
}

/// The machine's oracle store, read from this process's environment.
pub fn oracle_store_root() -> Option<PathBuf> {
    oracle_store_root_in(
        std::env::var_os(ORACLE_STORE_ENV).as_deref(),
        std::env::var_os("XDG_CACHE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// The toolchain `checkout`'s `rust-toolchain.toml` names, which
/// `scripts/build-sce.sh` builds with: the name on the first line that is
/// exactly `channel = "<name>"`. `None` when there is no such line, or when the
/// name holds a character outside `[A-Za-z0-9._+-]`, because the name is a path
/// component of a store entry. The shell reading is `sce_codegen_toolchain`.
pub fn toolchain_channel(checkout: &Path) -> Option<String> {
    let text = std::fs::read_to_string(checkout.join("rust-toolchain.toml")).ok()?;
    let channel = text
        .split('\n')
        .find_map(|line| line.strip_prefix("channel = \"")?.strip_suffix('"'))?;
    let named = !channel.is_empty()
        && channel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    named.then(|| channel.to_owned())
}

/// Where `store` keeps the `sce-codegen` built from `sce_workspace`'s source
/// state with `checkout`'s recipe and toolchain,
/// `<store>/sce-codegen/<rev>-<dirty digest>-<recipe digest>-<toolchain>`,
/// whether it is there or not. `None` when a part of the name cannot be
/// established. The shell reading is `sce_codegen_store_entry`.
pub fn sce_codegen_store_entry(
    store: &Path,
    checkout: &Path,
    sce_workspace: &Path,
) -> Option<PathBuf> {
    let made_from =
        crate::vendored_recipe_token(sce_workspace, &[checkout.join(SCE_CODEGEN_RECIPE)])?;
    let channel = toolchain_channel(checkout)?;
    Some(
        store
            .join("sce-codegen")
            .join(format!("{made_from}-{channel}")),
    )
}

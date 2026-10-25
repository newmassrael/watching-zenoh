// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-policies.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], whose
//! `Default` is the value the build's environment states as `WZ_POLICY_<NAME>`, or upstream's
//! behaviour when it states none. A test names the other value by setting the field.

/// What this build decided beyond upstream's behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionPolicy {}

impl SessionPolicy {
    /// The policy this build states: its environment's values, else upstream's.
    pub const fn from_build() -> Self {
        Self {}
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The option fields pico declares only with its unstable API, read the same way in
//! both header arms.
//!
//! `reliability`, `source_info` and `cancellation_token` sit inside
//! `#ifdef Z_FEATURE_UNSTABLE_API` in pico's option structs
//! (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`), so a build without
//! `unstable-api` must not have them: the struct a program allocates is the smaller one
//! its header declares. What pico's `api.c` uses in their place is fixed per field (the
//! default reliability, no source info, no token), so each struct gets one method per
//! field, named as the field, that answers the field where it exists and that value
//! where it does not. A caller then reads `options.source_info()` in either arm.

/// Give `$ty` a method per unstable-API field: the field itself with `unstable-api`,
/// `$absent` without it.
macro_rules! unstable_option_fields {
    ($ty:ty { $($field:ident : $t:ty = $absent:expr),+ $(,)? }) => {
        impl $ty {
            $(
                #[cfg(feature = "unstable-api")]
                #[inline]
                pub(crate) fn $field(&self) -> $t {
                    self.$field
                }

                #[cfg(not(feature = "unstable-api"))]
                #[inline]
                pub(crate) fn $field(&self) -> $t {
                    $absent
                }
            )+
        }
    };
}

pub(crate) use unstable_option_fields;

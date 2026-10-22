// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! pico's `z_locality_t`, and the locality an entity of this drop-in has.
//!
//! The option fields that carry a locality (`allowed_origin` on a subscriber and a
//! queryable, `allowed_destination` on a publisher, a put, a delete, a querier and a get)
//! exist only when pico's local subscriber or local queryable switch is on
//! (`vendor/zenoh-pico/include/zenoh-pico/api/types.h` @ `#if Z_FEATURE_LOCAL_SUBSCRIBER == 1`).
//! Without the switch pico passes `z_locality_default()` (ANY) and has no local path to
//! take, so its traffic is remote only; this crate says `Remote` for that arm. With the
//! switch, each struct's field is read through one method named as the field
//! ([`locality_option_field`]), so a caller is the same in both arms.

use std::ffi::c_int;

#[cfg(any(feature = "local-subscriber", feature = "local-queryable", test))]
use wz_runtime_tokio::locality::Locality;

/// pico `z_locality_t`, an enum passed as an `int`.
pub type z_locality_t = c_int;

/// pico `Z_LOCALITY_ANY`: session-local and remote traffic.
pub const Z_LOCALITY_ANY: z_locality_t = 0;
/// pico `Z_LOCALITY_SESSION_LOCAL`: session-local traffic only.
pub const Z_LOCALITY_SESSION_LOCAL: z_locality_t = 1;
/// pico `Z_LOCALITY_REMOTE`: remote traffic only.
pub const Z_LOCALITY_REMOTE: z_locality_t = 2;

/// A caller's `z_locality_t` as wz's [`Locality`]. The values agree numerically. A value
/// pico does not name admits both directions, as pico's own predicates read it
/// (`vendor/zenoh-pico/include/zenoh-pico/utils/locality.h` @
/// `static inline bool _z_locality_allows_local(z_locality_t locality) {`, whose `default`
/// arm is the ANY arm), which is [`Locality::Any`]. Only an arm with a locality field
/// has a value to read.
#[cfg(any(feature = "local-subscriber", feature = "local-queryable", test))]
pub(crate) fn locality_from_pico(value: z_locality_t) -> Locality {
    match value {
        Z_LOCALITY_SESSION_LOCAL => Locality::SessionLocal,
        Z_LOCALITY_REMOTE => Locality::Remote,
        _ => Locality::Any,
    }
}

/// The locality an entity takes when its options are NULL or its arm has no field: what
/// `z_*_options_default` writes, `Z_LOCALITY_ANY`, with the switch `feature` on; remote
/// only without it.
macro_rules! default_locality {
    ($feature:literal) => {{
        #[cfg(feature = $feature)]
        let locality = wz_runtime_tokio::locality::Locality::Any;
        #[cfg(not(feature = $feature))]
        let locality = wz_runtime_tokio::locality::Locality::Remote;
        locality
    }};
}

/// Give `$ty` a method `$field()` answering the struct's locality field as a
/// [`Locality`](wz_runtime_tokio::locality::Locality)
/// with the switch `$feature` on, and `Remote` without it (the field is then absent).
macro_rules! locality_option_field {
    ($ty:ty, $field:ident, $feature:literal) => {
        impl $ty {
            #[cfg(feature = $feature)]
            #[inline]
            pub(crate) fn $field(&self) -> wz_runtime_tokio::locality::Locality {
                crate::locality::locality_from_pico(self.$field)
            }

            #[cfg(not(feature = $feature))]
            #[inline]
            pub(crate) fn $field(&self) -> wz_runtime_tokio::locality::Locality {
                wz_runtime_tokio::locality::Locality::Remote
            }
        }
    };
}

pub(crate) use {default_locality, locality_option_field};

#[cfg(test)]
mod tests {
    use super::*;

    /// The three values agree with wz's numbering, and a value pico does not name
    /// admits both directions, as pico's predicates' `default` arm does.
    #[test]
    fn a_pico_locality_reads_as_pico_reads_it() {
        assert_eq!(locality_from_pico(Z_LOCALITY_ANY), Locality::Any);
        assert_eq!(
            locality_from_pico(Z_LOCALITY_SESSION_LOCAL),
            Locality::SessionLocal
        );
        assert_eq!(locality_from_pico(Z_LOCALITY_REMOTE), Locality::Remote);
        assert_eq!(locality_from_pico(7), Locality::Any);
        assert_eq!(locality_from_pico(-1), Locality::Any);
    }
}

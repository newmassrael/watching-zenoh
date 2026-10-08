// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which part is on the bus, read from the Device Identification register.
//!
//! The OPEN Alliance `OA_PHYID` register cannot say: on this family it reflects
//! the integrated PHY's clause 22 identifier rather than the product (errata item
//! s1, DS80001075F 1.1), so it names the PHY block and not the part. The product
//! and silicon revision are in `DEVID` (MMS 10, address 0x0094; DS60001734F
//! 11.6.6), and only there.

/// The product, from `DEVID.MODEL` (bits 19:4): `0x8650` is the LAN8650 and
/// `0x8651` the LAN8651 (DS60001734F 11.6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Lan8650,
    Lan8651,
}

/// The silicon revision, from `DEVID.REV` (bits 3:0).
///
/// DS60001734F 11.6.6 lists values 1 and 2, and DS80001075F Table 1 names them:
/// 1 is product revision B0 and 2 is B1. AN1760 (DS60001760G) says its
/// configuration holds for these and newer versions until a newer revision of the
/// note supersedes it, so a value above 2 is a part no document grades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revision {
    /// `REV` 1, product revision B0.
    B0,
    /// `REV` 2, product revision B1.
    B1,
    /// `REV` 3 or above: a revision newer than the documents this crate was
    /// written from.
    Newer(u8),
}

/// A part this crate recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub product: Product,
    pub revision: Revision,
}

/// Why a `DEVID` value is not a part this crate drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// `MODEL` is neither `0x8650` nor `0x8651`. A bus that reads back all ones or
    /// all zeros (no chip, a chip in reset) lands here.
    UnknownModel(u16),
    /// `REV` is 0, which no document assigns.
    UnknownRevision(u8),
}

/// Read a `DEVID` value.
///
/// Pure: it looks at `MODEL` and `REV` and at nothing else, so the reserved bits
/// around them do not matter. A `REV` of 3 or above is returned as
/// [`Revision::Newer`] and is not an error here; whether to drive such a part is
/// the caller's policy (`Config::accept_newer_revisions`).
pub const fn identify(devid: u32) -> Result<Identity, IdentityError> {
    let model = ((devid >> 4) & 0xFFFF) as u16;
    let rev = (devid & 0xF) as u8;
    let product = match model {
        0x8650 => Product::Lan8650,
        0x8651 => Product::Lan8651,
        other => return Err(IdentityError::UnknownModel(other)),
    };
    let revision = match rev {
        0 => return Err(IdentityError::UnknownRevision(0)),
        1 => Revision::B0,
        2 => Revision::B1,
        newer => Revision::Newer(newer),
    };
    Ok(Identity { product, revision })
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The parameters of a CRC and the table derived from them: what a profile names and checks once,
//! when it is read, so that the engine a frame's CRC is fed through is built with the profile and
//! not per frame. The digest that feeds bytes through the table is `wz-app-frame`'s (`e2e_crc`),
//! which re-exports these items at the paths they had there; the model and the published sets it
//! is graded against are described in that module.
//!
//! # How the table form is derived from the model
//!
//! With `refin` set, the register is held REFLECTED (bit 0 is the highest
//! power), so a byte is combined by XOR at the bottom and the register shifts
//! right, with the reflected polynomial. With it clear, the register is held
//! in the normal orientation, the byte is combined at the top and the register
//! shifts left. At the end the register is reflected exactly when `refin` and
//! `refout` disagree, because a register held reflected is already in the
//! `refout` orientation when `refout` is set. The digest's tests grade this
//! against the model's bit-at-a-time definition on random parameter sets, so
//! the derivation is checked rather than argued.

use core::fmt;

/// The widths the engine implements.
pub const SUPPORTED_WIDTHS: [u8; 4] = [8, 16, 32, 64];

/// The six parameters of the catalogue's model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcParams {
    /// 8, 16, 32 or 64.
    pub width: u8,
    /// The polynomial without its `x^width` term, normal orientation.
    pub poly: u64,
    /// The register's start value, normal orientation.
    pub init: u64,
    /// Whether each input byte is reflected before it enters the register.
    pub refin: bool,
    /// Whether the register is reflected before `xorout` is applied.
    pub refout: bool,
    /// XORed into the result last.
    pub xorout: u64,
}

/// Why a set of parameters cannot drive the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrcParamsError {
    /// The width is not one of [`SUPPORTED_WIDTHS`].
    UnsupportedWidth(u8),
    /// A parameter has a bit set above the width.
    DoesNotFit {
        /// Which parameter: `poly`, `init` or `xorout`.
        what: &'static str,
        /// The value given.
        value: u64,
        /// The width it was meant to fit.
        width: u8,
    },
}

impl fmt::Display for CrcParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWidth(w) => write!(
                f,
                "a CRC width of {w} bits is not supported (the engine implements 8, 16, 32 and 64)"
            ),
            Self::DoesNotFit { what, value, width } => write!(
                f,
                "the CRC {what} {value:#x} does not fit the {width}-bit width"
            ),
        }
    }
}

/// The all-ones value of `width` bits.
#[inline]
pub fn width_mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

/// `value` with its low `width` bits in reverse order. Bits above `width` must
/// be clear.
#[inline]
pub fn reflect(value: u64, width: u8) -> u64 {
    value.reverse_bits() >> (64 - u32::from(width))
}

/// A CRC engine: the parameters and the 256-entry table derived from them.
///
/// Built once, by whoever holds the parameters: a profile builds the engine of
/// its CRC when it is read, so feeding a frame costs only the bytes fed. The
/// table costs 2048 inner steps, which is why it is not built per frame.
#[derive(Debug, Clone)]
pub struct Crc {
    params: CrcParams,
    table: [u64; 256],
}

impl Crc {
    /// An engine for `params`, or the reason they cannot be one.
    pub fn new(params: CrcParams) -> Result<Self, CrcParamsError> {
        if !SUPPORTED_WIDTHS.contains(&params.width) {
            return Err(CrcParamsError::UnsupportedWidth(params.width));
        }
        let mask = width_mask(params.width);
        for (what, value) in [
            ("poly", params.poly),
            ("init", params.init),
            ("xorout", params.xorout),
        ] {
            if value & !mask != 0 {
                return Err(CrcParamsError::DoesNotFit {
                    what,
                    value,
                    width: params.width,
                });
            }
        }

        let mut table = [0u64; 256];
        if params.refin {
            let poly = reflect(params.poly, params.width);
            for (index, slot) in table.iter_mut().enumerate() {
                let mut r = index as u64;
                for _ in 0..8 {
                    r = if r & 1 != 0 { (r >> 1) ^ poly } else { r >> 1 };
                }
                *slot = r;
            }
        } else {
            let top = 1u64 << (params.width - 1);
            for (index, slot) in table.iter_mut().enumerate() {
                let mut r = (index as u64) << (params.width - 8);
                for _ in 0..8 {
                    r = if r & top != 0 {
                        (r << 1) ^ params.poly
                    } else {
                        r << 1
                    };
                }
                *slot = r & mask;
            }
        }
        Ok(Self { params, table })
    }

    /// The parameters this engine was built from.
    #[inline]
    pub fn params(&self) -> &CrcParams {
        &self.params
    }

    /// The table derived from the parameters, indexed by the byte combined with
    /// the register in the orientation `refin` gives it.
    #[inline]
    pub fn table(&self) -> &[u64; 256] {
        &self.table
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A CRC engine for the widths 8, 16, 32 and 64, parameterised the way the
//! public catalogue parameterises one.
//!
//! # Why a generic engine and not two fixed ones
//!
//! The end-to-end protection header this crate reads and builds
//! (`e2e_profile`) is described by the CALLER, one profile per call, and a
//! profile names its own CRC. Hard-coding the two polynomials a given
//! deployment happens to use would make this library a copy of that
//! deployment's constants, in a repository that is public. What lives here is
//! the MECHANISM: the Rocksoft model's six parameters and an engine that
//! honours all of them. The parameter sets in this file's tests are the
//! catalogue's own published ones, each with the check value the catalogue
//! prints for the ASCII text `123456789`.
//!
//! # The model
//!
//! `width`, `poly`, `init`, `refin`, `refout` and `xorout` are the parameter
//! names of the Rocksoft model, defined in section 15 of Williams, "A Painless
//! Guide to CRC Error Detection Algorithms" (1993), which the catalogue below
//! names as the model it specifies its algorithms in. `poly` is written without
//! its top bit and in the UNREFLECTED orientation even for a reflected
//! algorithm ("the bottom bit of this parameter is always the LSB of the
//! divisor"); reflection is framed as an input and an output transformation:
//! `refin` reflects every input byte before it is processed, `refout` reflects
//! the final register before `xorout` is XORed in. (The paper's sentence on
//! `refin` is printed with its TRUE and FALSE swapped in one of its two
//! halves; the catalogue entries below fix the intended sense, and the check
//! values here only come out with `refin == true` meaning "reflect".)
//!
//! Source of every published value in this file: Cook, "Catalogue of
//! parametrised CRC algorithms", <https://reveng.sourceforge.io/crc-catalogue/all.htm>
//! (the page read on 2026-10-08). `refin` and `refout` are independent here
//! because the model makes them so. The catalogue lists no 8-, 16-, 32- or
//! 64-bit algorithm that sets them differently (its only such entry,
//! CRC-12/UMTS, is 12 bits wide), so a mixed pair is graded against the plain
//! bitwise reference in the tests and has no published check value.
//!
//! # How the table form is derived from the model
//!
//! With `refin` set, the register is held REFLECTED (bit 0 is the highest
//! power), so a byte is combined by XOR at the bottom and the register shifts
//! right, with the reflected polynomial. With it clear, the register is held
//! in the normal orientation, the byte is combined at the top and the register
//! shifts left. At the end the register is reflected exactly when `refin` and
//! `refout` disagree, because a register held reflected is already in the
//! `refout` orientation when `refout` is set. The tests grade this against
//! the model's bit-at-a-time definition on random parameter sets, so the
//! derivation is checked rather than argued.

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
pub(crate) fn width_mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

/// `value` with its low `width` bits in reverse order. Bits above `width` must
/// be clear.
fn reflect(value: u64, width: u8) -> u64 {
    value.reverse_bits() >> (64 - u32::from(width))
}

/// A CRC engine: the parameters and the 256-entry table derived from them.
///
/// Built per use. The table costs 2048 inner steps, which is below the cost of
/// anything a caller does with the result, and keeping no process-wide cache
/// is what lets the doors above stay stateless.
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
    pub fn params(&self) -> &CrcParams {
        &self.params
    }

    /// A running computation, to be fed the input in pieces.
    pub fn start(&self) -> Digest<'_> {
        let register = if self.params.refin {
            reflect(self.params.init, self.params.width)
        } else {
            self.params.init
        };
        Digest {
            crc: self,
            register,
        }
    }

    /// The CRC of `data` taken in one piece.
    pub fn checksum(&self, data: &[u8]) -> u64 {
        let mut digest = self.start();
        digest.update(data);
        digest.finish()
    }
}

/// A CRC in progress. Feeding `a` then `b` is the same as feeding `a ++ b`,
/// which is what lets a caller take the input from several places in a fixed
/// order without joining them first.
#[derive(Debug, Clone)]
pub struct Digest<'a> {
    crc: &'a Crc,
    register: u64,
}

impl Digest<'_> {
    /// Feed `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        let table = &self.crc.table;
        if self.crc.params.refin {
            for &byte in bytes {
                let index = ((self.register ^ u64::from(byte)) & 0xff) as usize;
                self.register = (self.register >> 8) ^ table[index];
            }
        } else {
            let width = self.crc.params.width;
            let mask = width_mask(width);
            let shift = u32::from(width) - 8;
            for &byte in bytes {
                let index = (((self.register >> shift) as u8) ^ byte) as usize;
                self.register = ((self.register << 8) ^ table[index]) & mask;
            }
        }
    }

    /// The finished CRC.
    pub fn finish(self) -> u64 {
        let params = &self.crc.params;
        let out = if params.refin == params.refout {
            self.register
        } else {
            reflect(self.register, params.width)
        };
        out ^ params.xorout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    /// The text every catalogue entry's `check` is taken over.
    const CHECK_INPUT: &[u8] = b"123456789";

    /// Published parameter sets with the check value the catalogue prints for
    /// each, copied from the page named in the module doc. The selection spans
    /// all four widths, both orientations, every combination of a non-zero
    /// `init` and `xorout`, and an `init` whose bit pattern is not its own
    /// reflection (0xc6c6, 0x89ec, 0x1d0f, 0xc7, 0x800d), which is what shows
    /// the register is started in the right orientation: an all-ones or all-zero
    /// `init` reads the same either way.
    #[rustfmt::skip]
    fn published() -> Vec<(&'static str, CrcParams, u64)> {
        let p = |width, poly, init, refin, refout, xorout| CrcParams { width, poly, init, refin, refout, xorout };
        alloc::vec![
            ("CRC-8/AUTOSAR",    p(8,  0x2f, 0xff, false, false, 0xff), 0xdf),
            ("CRC-8/SAE-J1850",  p(8,  0x1d, 0xff, false, false, 0xff), 0x4b),
            ("CRC-8/SMBUS",      p(8,  0x07, 0x00, false, false, 0x00), 0xf4),
            ("CRC-8/MAXIM-DOW",  p(8,  0x31, 0x00, true,  true,  0x00), 0xa1),
            ("CRC-8/ROHC",       p(8,  0x07, 0xff, true,  true,  0x00), 0xd0),
            ("CRC-8/MIFARE-MAD", p(8,  0x1d, 0xc7, false, false, 0x00), 0x99),
            ("CRC-16/IBM-3740",  p(16, 0x1021, 0xffff, false, false, 0x0000), 0x29b1),
            ("CRC-16/XMODEM",    p(16, 0x1021, 0x0000, false, false, 0x0000), 0x31c3),
            ("CRC-16/GENIBUS",   p(16, 0x1021, 0xffff, false, false, 0xffff), 0xd64e),
            ("CRC-16/ARC",       p(16, 0x8005, 0x0000, true,  true,  0x0000), 0xbb3d),
            ("CRC-16/MCRF4XX",   p(16, 0x1021, 0xffff, true,  true,  0x0000), 0x6f91),
            ("CRC-16/IBM-SDLC",  p(16, 0x1021, 0xffff, true,  true,  0xffff), 0x906e),
            ("CRC-16/ISO-IEC-14443-3-A", p(16, 0x1021, 0xc6c6, true,  true,  0x0000), 0xbf05),
            ("CRC-16/TMS37157",  p(16, 0x1021, 0x89ec, true,  true,  0x0000), 0x26b1),
            ("CRC-16/SPI-FUJITSU", p(16, 0x1021, 0x1d0f, false, false, 0x0000), 0xe5cc),
            ("CRC-16/DDS-110",   p(16, 0x8005, 0x800d, false, false, 0x0000), 0x9ecf),
            ("CRC-16/DECT-R",    p(16, 0x0589, 0x0000, false, false, 0x0001), 0x007e),
            ("CRC-32/AUTOSAR",   p(32, 0xf4acfb13, 0xffff_ffff, true,  true,  0xffff_ffff), 0x1697_d06a),
            ("CRC-32/ISO-HDLC",  p(32, 0x04c11db7, 0xffff_ffff, true,  true,  0xffff_ffff), 0xcbf4_3926),
            ("CRC-32/ISCSI",     p(32, 0x1edc6f41, 0xffff_ffff, true,  true,  0xffff_ffff), 0xe306_9283),
            ("CRC-32/MPEG-2",    p(32, 0x04c11db7, 0xffff_ffff, false, false, 0x0000_0000), 0x0376_e6e7),
            ("CRC-32/BZIP2",     p(32, 0x04c11db7, 0xffff_ffff, false, false, 0xffff_ffff), 0xfc89_1918),
            ("CRC-32/CKSUM",     p(32, 0x04c11db7, 0x0000_0000, false, false, 0xffff_ffff), 0x765e_7680),
            ("CRC-64/XZ",        p(64, 0x42f0_e1eb_a9ea_3693, u64::MAX, true,  true,  u64::MAX), 0x995d_c9bb_df19_39fa),
            ("CRC-64/ECMA-182",  p(64, 0x42f0_e1eb_a9ea_3693, 0, false, false, 0), 0x6c40_df5f_0b49_7347),
            ("CRC-64/WE",        p(64, 0x42f0_e1eb_a9ea_3693, u64::MAX, false, false, u64::MAX), 0x62ec_59e3_f1a4_f00a),
            ("CRC-64/GO-ISO",    p(64, 0x1b, u64::MAX, true,  true,  u64::MAX), 0xb909_56c7_75a4_1001),
        ]
    }

    /// The model written the plainest way there is: one input bit at a time,
    /// register in the normal orientation, reflection applied literally to
    /// each byte and to the result. It shares no table and no orientation
    /// trick with [`Crc`], which is the point of it.
    fn bitwise(params: &CrcParams, data: &[u8]) -> u64 {
        let width = u32::from(params.width);
        let mask = width_mask(params.width);
        let top = 1u64 << (width - 1);
        let reflect_bits = |value: u64, bits: u32| {
            let mut out = 0u64;
            for i in 0..bits {
                if value & (1 << i) != 0 {
                    out |= 1 << (bits - 1 - i);
                }
            }
            out
        };
        let mut register = params.init;
        for &byte in data {
            let byte = if params.refin {
                reflect_bits(u64::from(byte), 8)
            } else {
                u64::from(byte)
            };
            register ^= byte << (width - 8);
            for _ in 0..8 {
                let carry = register & top != 0;
                register = (register << 1) & mask;
                if carry {
                    register ^= params.poly;
                }
            }
        }
        if params.refout {
            register = reflect_bits(register, width);
        }
        register ^ params.xorout
    }

    /// A small deterministic generator, so the random comparisons repeat.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    #[test]
    fn every_published_parameter_set_gives_the_published_check_value() {
        for (name, params, check) in published() {
            let crc = Crc::new(params).expect("a published set is valid");
            assert_eq!(
                crc.checksum(CHECK_INPUT),
                check,
                "{name}: expected the catalogue's check value {check:#x}"
            );
        }
    }

    /// The mutants the brief names, as PARAMETER mutants: each of them must
    /// move the check value of the two sets this feature is built on, so a
    /// check value is shown to be able to tell the wrong algorithm from the
    /// right one. (Mutating the engine itself is graded by the red-first runs
    /// recorded with the round.)
    #[test]
    fn a_wrong_parameter_cannot_reproduce_a_published_check_value() {
        for name in [
            "CRC-32/AUTOSAR",
            "CRC-64/XZ",
            "CRC-16/MCRF4XX",
            "CRC-8/AUTOSAR",
        ] {
            let (_, params, check) = published()
                .into_iter()
                .find(|(n, _, _)| *n == name)
                .expect("in the table");
            let mutants = [
                (
                    "refin flipped",
                    CrcParams {
                        refin: !params.refin,
                        ..params
                    },
                ),
                (
                    "refout flipped",
                    CrcParams {
                        refout: !params.refout,
                        ..params
                    },
                ),
                (
                    "init wrong",
                    CrcParams {
                        init: params.init ^ 1,
                        ..params
                    },
                ),
                (
                    "xorout dropped",
                    CrcParams {
                        xorout: 0,
                        ..params
                    },
                ),
                (
                    "poly one bit off",
                    CrcParams {
                        poly: params.poly ^ 0x8,
                        ..params
                    },
                ),
            ];
            for (what, mutant) in mutants {
                if mutant == params {
                    // xorout was already zero: not a mutant of this set.
                    continue;
                }
                let got = Crc::new(mutant).expect("still valid").checksum(CHECK_INPUT);
                assert_ne!(
                    got, check,
                    "{name}: the mutant `{what}` reproduced the check value"
                );
            }
        }
    }

    #[test]
    fn the_engine_agrees_with_the_bitwise_model_on_random_input() {
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        // The published sets first: parameters that are known to be meaningful.
        let mut cases: Vec<CrcParams> = published().into_iter().map(|(_, p, _)| p).collect();
        // Then random ones, with `refin` and `refout` chosen independently.
        for _ in 0..200 {
            let width = SUPPORTED_WIDTHS[(rng.next() % 4) as usize];
            let mask = width_mask(width);
            cases.push(CrcParams {
                width,
                poly: rng.next() & mask,
                init: rng.next() & mask,
                refin: rng.next() & 1 == 1,
                refout: rng.next() & 1 == 1,
                xorout: rng.next() & mask,
            });
        }
        for params in cases {
            let crc = Crc::new(params).expect("valid");
            for len in [0usize, 1, 2, 7, 8, 9, 31, 64, 257] {
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                assert_eq!(
                    crc.checksum(&data),
                    bitwise(&params, &data),
                    "{params:?} over {len} bytes"
                );
            }
        }
    }

    #[test]
    fn mixed_reflection_is_exercised_not_just_allowed() {
        // No published 8/16/32/64-bit set has refin != refout, so make sure
        // the random comparison above really contains such sets and that they
        // differ from their both-reflected twin.
        let base = CrcParams {
            width: 16,
            poly: 0x1021,
            init: 0x1234,
            refin: true,
            refout: true,
            xorout: 0,
        };
        let mixed = CrcParams {
            refout: false,
            ..base
        };
        let a = Crc::new(base).expect("valid").checksum(CHECK_INPUT);
        let b = Crc::new(mixed).expect("valid").checksum(CHECK_INPUT);
        assert_eq!(
            b,
            reflect(a, 16),
            "refout is the last reflection and nothing else"
        );
        assert_eq!(b, bitwise(&mixed, CHECK_INPUT));
    }

    #[test]
    fn feeding_in_pieces_is_feeding_the_whole() {
        let (_, params, check) = published()
            .into_iter()
            .find(|(n, _, _)| *n == "CRC-32/AUTOSAR")
            .expect("in the table");
        let crc = Crc::new(params).expect("valid");
        for cut in 0..=CHECK_INPUT.len() {
            let mut digest = crc.start();
            digest.update(&CHECK_INPUT[..cut]);
            digest.update(&CHECK_INPUT[cut..]);
            assert_eq!(digest.finish(), check, "cut at {cut}");
        }
    }

    #[test]
    fn parameters_that_cannot_drive_the_engine_are_refused_by_name() {
        let ok = CrcParams {
            width: 32,
            poly: 0xf4ac_fb13,
            init: 0xffff_ffff,
            refin: true,
            refout: true,
            xorout: 0xffff_ffff,
        };
        assert!(Crc::new(ok).is_ok(), "the control is valid");
        for width in [0u8, 4, 7, 12, 24, 48, 65] {
            let err = Crc::new(CrcParams { width, ..ok }).expect_err("unsupported");
            assert_eq!(err, CrcParamsError::UnsupportedWidth(width));
            assert!(err.to_string().contains("not supported"), "{err}");
        }
        let narrow = CrcParams {
            width: 8,
            poly: 0x2f,
            init: 0xff,
            xorout: 0xff,
            ..ok
        };
        assert!(Crc::new(narrow).is_ok(), "the 8-bit control is valid");
        for (what, params) in [
            (
                "poly",
                CrcParams {
                    poly: 0x12f,
                    ..narrow
                },
            ),
            (
                "init",
                CrcParams {
                    init: 0x1ff,
                    ..narrow
                },
            ),
            (
                "xorout",
                CrcParams {
                    xorout: 0x1ff,
                    ..narrow
                },
            ),
        ] {
            match Crc::new(params).expect_err("does not fit") {
                CrcParamsError::DoesNotFit {
                    what: got, width, ..
                } => {
                    assert_eq!((got, width), (what, 8));
                }
                other => panic!("{what}: {other:?}"),
            }
        }
    }
}

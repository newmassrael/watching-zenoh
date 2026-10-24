//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-codec 1.10.1, file
// src/core/zint.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).
use core::convert::TryFrom;

use zenoh_buffers::{
    reader::{DidntRead, Reader},
    writer::{DidntWrite, Writer},
};

use crate::{LCodec, RCodec, WCodec, Zenoh080, Zenoh080Bounded};

const VLE_LEN_MAX: usize = vle_len(u64::MAX);

const fn vle_len(x: u64) -> usize {
    const B1: u64 = u64::MAX << 7;
    const B2: u64 = u64::MAX << (7 * 2);
    const B3: u64 = u64::MAX << (7 * 3);
    const B4: u64 = u64::MAX << (7 * 4);
    const B5: u64 = u64::MAX << (7 * 5);
    const B6: u64 = u64::MAX << (7 * 6);
    const B7: u64 = u64::MAX << (7 * 7);
    const B8: u64 = u64::MAX << (7 * 8);

    if (x & B1) == 0 {
        1
    } else if (x & B2) == 0 {
        2
    } else if (x & B3) == 0 {
        3
    } else if (x & B4) == 0 {
        4
    } else if (x & B5) == 0 {
        5
    } else if (x & B6) == 0 {
        6
    } else if (x & B7) == 0 {
        7
    } else if (x & B8) == 0 {
        8
    } else {
        9
    }
}

impl LCodec<u64> for Zenoh080 {
    fn w_len(self, x: u64) -> usize {
        vle_len(x)
    }
}

impl LCodec<usize> for Zenoh080 {
    fn w_len(self, x: usize) -> usize {
        self.w_len(x as u64)
    }
}

impl LCodec<u32> for Zenoh080 {
    fn w_len(self, x: u32) -> usize {
        self.w_len(x as u64)
    }
}

impl LCodec<u16> for Zenoh080 {
    fn w_len(self, x: u16) -> usize {
        self.w_len(x as u64)
    }
}

impl LCodec<u8> for Zenoh080 {
    fn w_len(self, _: u8) -> usize {
        1
    }
}

// u8
impl<W> WCodec<u8, &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    #[inline(always)]
    fn write(self, writer: &mut W, x: u8) -> Self::Output {
        writer.write_u8(x)
    }
}

impl<R> RCodec<u8, &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    #[inline(always)]
    fn read(self, reader: &mut R) -> Result<u8, Self::Error> {
        reader.read_u8()
    }
}

// u64
impl<W> WCodec<u64, &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, mut x: u64) -> Self::Output {
        // The slot is `VLE_LEN_MAX` long, the most a value takes: `x` loses seven bits to every
        // byte but the last, so the loop runs at most `VLE_LEN_MAX` times and the indexing is
        // within the slot. The slot is asked for whole whatever the value, as upstream's is, so a
        // bounded writer refuses a value it has fewer than `VLE_LEN_MAX` bytes left for: the
        // packing of a batch is part of the behaviour.
        let write = move |buffer: &mut [u8]| {
            let mut len = 0;
            while (x & !0x7f_u64) != 0 {
                buffer[len] = (x as u8) | 0x80_u8;
                len += 1;
                x >>= 7;
            }
            // In case len == VLE_LEN_MAX then all the bits have already been written in the latest
            // iteration. Else we haven't written all the necessary bytes yet.
            if len != VLE_LEN_MAX {
                buffer[len] = x as u8;
                len += 1;
            }
            // The number of written bytes
            len
        };
        // SAFETY: the contract of `with_slot` is that `write` returns at most the slot's length,
        // which the loop above keeps (at most `VLE_LEN_MAX`).
        unsafe { writer.with_slot(VLE_LEN_MAX, write)? };
        Ok(())
    }
}

impl<R> RCodec<u64, &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<u64, Self::Error> {
        let mut b = reader.read_u8()?;

        let mut v = 0;
        let mut i = 0;
        // 7 * VLE_LEN is beyond the maximum number of shift bits: the ninth byte is a whole byte
        // of value, read whatever its high bit says.
        while (b & 0x80_u8) != 0 && i != 7 * (VLE_LEN_MAX - 1) {
            v |= ((b & 0x7f_u8) as u64) << i;
            b = reader.read_u8()?;
            i += 7;
        }
        v |= (b as u64) << i;
        Ok(v)
    }
}

// Derive impls
macro_rules! uint_impl {
    ($uint:ty) => {
        impl<W> WCodec<$uint, &mut W> for Zenoh080
        where
            W: Writer,
        {
            type Output = Result<(), DidntWrite>;

            fn write(self, writer: &mut W, x: $uint) -> Self::Output {
                self.write(writer, x as u64)
            }
        }

        // A value the type cannot hold is not read as its low bits: it is a message that is not
        // the one that was sent, so it is refused (upstream truncates it).
        impl<R> RCodec<$uint, &mut R> for Zenoh080
        where
            R: Reader,
        {
            type Error = DidntRead;

            fn read(self, reader: &mut R) -> Result<$uint, Self::Error> {
                let x: u64 = self.read(reader)?;
                <$uint>::try_from(x).map_err(|_| DidntRead)
            }
        }
    };
}

uint_impl!(u16);
uint_impl!(u32);
uint_impl!(usize);

macro_rules! uint_ref_impl {
    ($uint:ty) => {
        impl<W> WCodec<&$uint, &mut W> for Zenoh080
        where
            W: Writer,
        {
            type Output = Result<(), DidntWrite>;

            fn write(self, writer: &mut W, x: &$uint) -> Self::Output {
                self.write(writer, *x)
            }
        }
    };
}

uint_ref_impl!(u8);
uint_ref_impl!(u16);
uint_ref_impl!(u32);
uint_ref_impl!(u64);
uint_ref_impl!(usize);

// Encode unsigned integer and verify that the size boundaries are respected
macro_rules! zint_impl_codec {
    ($zint:ty, $bound:ty) => {
        impl<W> WCodec<$zint, &mut W> for Zenoh080Bounded<$bound>
        where
            W: Writer,
        {
            type Output = Result<(), DidntWrite>;

            fn write(self, writer: &mut W, x: $zint) -> Self::Output {
                if (x as u64 & !(<$bound>::MAX as u64)) != 0 {
                    return Err(DidntWrite);
                }
                Zenoh080.write(writer, x as u64)
            }
        }

        impl<R> RCodec<$zint, &mut R> for Zenoh080Bounded<$bound>
        where
            R: Reader,
        {
            type Error = DidntRead;

            // The value is held to the bound AND to the type it is read as: a bound wider than the
            // type (`Zenoh080Bounded<u64>` read as a `u8`) would otherwise keep the low bits of
            // a value the type cannot hold, as the direct reads of upstream do.
            #[inline(always)]
            fn read(self, reader: &mut R) -> Result<$zint, Self::Error> {
                let x: u64 = Zenoh080.read(reader)?;
                if (x & !(<$bound>::MAX as u64)) != 0 {
                    return Err(DidntRead);
                }
                <$zint>::try_from(x).map_err(|_| DidntRead)
            }
        }
    };
}
macro_rules! zint_impl {
    ($zint:ty) => {
        zint_impl_codec!($zint, u8);
        zint_impl_codec!($zint, u16);
        zint_impl_codec!($zint, u32);
        zint_impl_codec!($zint, u64);
        zint_impl_codec!($zint, usize);
    };
}

zint_impl!(u8);
zint_impl!(u16);
zint_impl!(u32);
zint_impl!(u64);
zint_impl!(usize);

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! INTERNAL pico codec symbols that public example programs link directly.
//!
//! `_z_zint_len` is not part of pico's public API — it lives in
//! `protocol/codec/core.h` behind an underscore — and upstream's `z_pub_thr.c`
//! calls it anyway, to size its payload so the encoded message lands on a round
//! number of bytes. A drop-in that exported only the documented surface would
//! fail to link the canonical throughput benchmark, which is the concrete reason
//! this crate's export policy is "what pico programs CALL", not "what pico
//! documents".
//!
//! Being a pure function of its argument, this one has an unusually strong
//! oracle available: the real `libzenohpico.so` built by
//! `scripts/build-zenoh-pico-cli.sh` exports it, so agreement can be checked
//! against upstream's own compiled code rather than against a table transcribed
//! from its source. `tests/zint_len_against_pico_oracle.rs` does exactly that
//! across every boundary and a swept range.

/// pico `_z_zint_len` (`src/protocol/codec.c:100-130`): how many bytes the VLE
/// encoding of `v` occupies.
///
/// pico expresses this as a mask ladder — `VLE_LEN<n>_MASK` is
/// `UINT64_MAX << (7 * n)`, so "fits in n bytes" is "no bits above 7n are set" —
/// and the last rung is 9, not 10: the ninth byte carries a full 8 bits rather
/// than 7, so 64 bits never need a tenth. That asymmetry is the part a
/// from-scratch `(bits + 6) / 7` would get wrong, and it is why the oracle test
/// sweeps the top of the range rather than sampling it.
#[no_mangle]
pub extern "C" fn _z_zint_len(v: u64) -> u8 {
    for n in 1..=8u32 {
        if v >> (7 * n) == 0 {
            return n as u8;
        }
    }
    9
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every boundary in the mask ladder, stated as the two values that
    /// straddle it. The ORACLE test proves agreement with upstream; this one
    /// keeps the shape readable and fails fast without a built pico.
    #[test]
    fn zint_len_boundaries() {
        assert_eq!(_z_zint_len(0), 1);
        assert_eq!(_z_zint_len(127), 1);
        assert_eq!(_z_zint_len(128), 2);
        assert_eq!(_z_zint_len((1 << 14) - 1), 2);
        assert_eq!(_z_zint_len(1 << 14), 3);
        assert_eq!(_z_zint_len((1 << 56) - 1), 8);
        // The ninth byte carries 8 bits, not 7 — so 2^56 through u64::MAX all
        // cost 9, and there is no tenth rung.
        assert_eq!(_z_zint_len(1 << 56), 9);
        assert_eq!(_z_zint_len(u64::MAX), 9);
    }
}

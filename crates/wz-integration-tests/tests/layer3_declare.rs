// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `declare` codec (§5 DECLARE network
//! envelope; R110a-d wz-side authoring, R110e Layer 3 byte-compare).
//!
//! Closes the application-layer codec catalog wire-interop axis at
//! 7/7 MIDs (push 0x1D / oam 0x1F / request 0x1C / response 0x1B /
//! response_final 0x1A / interest 0x19 / declare 0x1E). DECLARE was
//! the last unmodeled envelope after R101-R108b; the R110 sub-rounds
//! lifted all 9 declaration sub-MIDs to wz authoring before this
//! Layer 3 round so the wire-compare here exercises the full chain
//! from envelope dispatch through the declared default arm
//! (`DeclFinal`) one byte at a time.
//!
//! Default-state fixture is 2-patch:
//!
//! 1. `_ext_qos._val = 5` matches `_Z_N_QOS_DEFAULT._val` so
//!    `_z_declare_encode`'s qos-needed check evaluates false and the
//!    envelope's Z flag stays clear. Same pattern as PUSH/RESPONSE/
//!    REQUEST default fixtures.
//! 2. `_decl._tag = 8 = _Z_DECL_FINAL` overrides the zero-init tag
//!    of 0 (= _Z_DECL_KEXPR; first enum variant by declaration order
//!    in `_z_declaration_t._tag`). Without this patch the inner
//!    dispatch reaches `_z_decl_kexpr_encode` and emits `[0x00,
//!    0x00, 0x00]` (3 bytes: decl_kexpr header + id VLE + wireexpr
//!    id VLE). With the patch the inner dispatch reaches
//!    `_z_decl_final_encode` (1 byte: `[0x1A]`) — matching wz's R88
//!    declared default arm `DeclFinal::default()`.
//!
//! Wire shape: `[0x1E, 0x1A]` = 2 bytes = envelope header
//! (MID 0x1E, no I, no Z) + decl_final inner header (MID 0x1A).

use wz_codecs::declare::Declare;
use zenoh_pico_sys::{
    _z_declare_encode, _z_n_msg_declare_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
};

// `_z_declaration_t._tag` is an anonymous enum in zenoh-pico's
// definitions/declarations.h; bindgen renders the variants as `u32`
// constants attached to the synthesized tag-enum type, but the
// `_tag` field itself is a plain `u32`-shaped slot. Match the
// `_Z_DECL_FINAL` ordinal (= 8, the 9th variant after the eight
// declared-and-undeclared sub-MIDs) by integer literal so this test
// stays robust to bindgen's exact naming for the anonymous enum.
const Z_DECL_FINAL_TAG: u32 = 8;

fn zenoh_pico_encode_declare_default() -> Vec<u8> {
    // SAFETY: standard wbuf-extract path. The `_decl._tag` write
    // targets a plain `u32` slot exposed by bindgen; the `_decl._body`
    // union is left zero-init, which is sound because
    // `_z_decl_final_encode` consults only `_Z_DECL_FINAL_MID` (a
    // constant) and not any field of `_body._decl_final` — the
    // upstream `_z_decl_final_t` holds only a placeholder bool that
    // the encoder ignores. Per declarations.c:131-135.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_declare_t::default();
        // (1) qos default sentinel — clears `_z_declare_encode`'s
        //     `has_qos_ext` so the envelope's Z flag stays clear.
        msg._ext_qos._val = 5;
        // (2) tag dispatch override — point the inner declaration
        //     at `_Z_DECL_FINAL` (= 8) so `_z_declaration_encode`
        //     reaches `_z_decl_final_encode`. Matches wz's R88
        //     declared default arm (DeclareVariant default =
        //     CodecZenohDeclFinal).
        msg._decl._tag = Z_DECL_FINAL_TAG;
        let ret = _z_declare_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_declare_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_declare_default_byte_equivalent() {
    let wz = Declare::default().encode_to_vec();
    let pico = zenoh_pico_encode_declare_default();
    assert_eq!(
        wz, pico,
        "default DECLARE must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x1E, 0x1A],
        "default wire form: declare_hdr (MID 0x1E, no flags) + decl_final inner hdr (MID 0x1A)"
    );
}

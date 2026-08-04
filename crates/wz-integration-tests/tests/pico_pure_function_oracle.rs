// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` — the exports that are PURE FUNCTIONS, checked
//! against upstream's own COMPILED code rather than against a table transcribed
//! from its source.
//!
//! ## Why these two get a stronger gate than the rest of the ABI
//!
//! Most of this crate's parity is behavioural and needs a running peer, so the
//! witness is a foreign process on the wire. `_z_zint_len` and `z_id_to_string`
//! are different: they are total functions of their argument with no session,
//! no wire and no timing. For those, the strongest available oracle is not a
//! peer at all — it is `libzenohpico.so` itself, which
//! `scripts/build-zenoh-pico-cli.sh` already builds. Both libraries are opened
//! side by side and their answers compared directly.
//!
//! That closes a specific failure mode a hand-written table cannot. Transcribing
//! a constant table from upstream source and asserting against it proves only
//! that the transcription matches the transcription; if the reading was wrong,
//! both sides are wrong together. Here nothing is transcribed — upstream's
//! compiled function is called.
//!
//! ## The two properties that a plausible implementation gets wrong
//!
//! **`_z_zint_len` has NINE rungs, not ten.** Its ladder is
//! `VLE_LEN<n>_MASK == UINT64_MAX << (7 * n)` for n in 1..=8, and then 9
//! (`src/protocol/codec.c:100-130`): the ninth byte carries a full 8 bits rather
//! than 7. A from-scratch `(64 + 6) / 7 == 10` is the obvious wrong answer, so
//! the sweep below covers every boundary AND the whole top of the range.
//!
//! **`z_id_to_string` is LITTLE-ENDIAN.** `_z_string_convert_bytes_le` fills its
//! buffer back-to-front (`src/collections/string.c:103-119`), so byte 0 of the
//! id renders LAST. Big-endian is equally plausible to read off the source and
//! would disagree with every id a pico program prints. The comparison is against
//! upstream's own output, so neither reading has to be trusted.
//!
//! ## Why `dlopen` rather than linking both
//!
//! wz's cdylib and `libzenohpico.so` export the SAME symbol names — that is the
//! entire point of a binary drop-in — so a program linking both would resolve
//! each name once and silently compare a library against itself, passing
//! unconditionally. Opening each with `RTLD_LOCAL` keeps the two namespaces
//! apart, which is what makes the comparison real. Damage-probed: pointing both
//! handles at the same library makes the mismatch assertions unreachable, which
//! is the shape this arrangement exists to avoid.

use std::path::PathBuf;

use libloading::{Library, Symbol};

/// pico `ZENOH_ID_SIZE`.
const ID_SIZE: usize = 16;

/// The wz cdylib under test.
fn wz_cdylib() -> PathBuf {
    let path = project_root().join("crates/target/debug/libwz_capi_pico.so");
    assert!(
        path.is_file(),
        "wz cdylib missing at {}; run `cargo build -p wz-capi-pico`",
        path.display()
    );
    path
}

/// The REAL zenoh-pico shared library — the oracle.
fn pico_library() -> PathBuf {
    let path = project_root().join("target/zenoh-pico-build/lib/libzenohpico.so");
    assert!(
        path.is_file(),
        "zenoh-pico shared library missing at {}; run \
         scripts/build-zenoh-pico-cli.sh first (it is the CMake build product, \
         and it is the ORACLE this file compares against -- without it there is \
         nothing to compare wz to, so this is a hard prereq, never a skip)",
        path.display()
    );
    path
}

fn project_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<root>/crates/wz-integration-tests`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("manifest dir has a grandparent")
        .to_path_buf()
}

/// Open a library in its OWN namespace. `libloading`'s default is
/// `RTLD_LAZY | RTLD_LOCAL`, which is what keeps the two `z_*` symbol sets from
/// resolving to whichever was loaded first.
///
/// # Safety
/// Loading a shared library runs its initialisers.
unsafe fn open(path: PathBuf) -> Library {
    Library::new(&path).unwrap_or_else(|e| panic!("dlopen {} failed: {e}", path.display()))
}

#[test]
fn zint_len_agrees_with_the_real_pico_library() {
    unsafe {
        let wz = open(wz_cdylib());
        let pico = open(pico_library());
        let wz_fn: Symbol<unsafe extern "C" fn(u64) -> u8> = wz
            .get(b"_z_zint_len\0")
            .expect("wz does not export _z_zint_len");
        let pico_fn: Symbol<unsafe extern "C" fn(u64) -> u8> = pico
            .get(b"_z_zint_len\0")
            .expect("libzenohpico.so does not export _z_zint_len");

        // Every rung boundary, both sides of it, plus the extremes.
        let mut probes: Vec<u64> = vec![0, 1, u64::MAX];
        for n in 1..=9u32 {
            let bits = 7 * n;
            if bits < 64 {
                probes.push((1u64 << bits) - 1);
                probes.push(1u64 << bits);
                probes.push(1u64 << (bits - 1));
            }
        }
        // A swept band across the top, where the 9-vs-10 rung error lives.
        for shift in 50..64 {
            probes.push(1u64 << shift);
            probes.push((1u64 << shift) | 0x5555_5555_5555_5555u64 >> (63 - shift));
        }
        // And a deterministic spread over the whole range (no RNG: a failing
        // case must be reproducible from the source alone).
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..4096 {
            probes.push(x);
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }

        for v in probes {
            assert_eq!(
                wz_fn(v),
                pico_fn(v),
                "_z_zint_len disagrees with upstream at v = {v} ({v:#x})"
            );
        }
    }
}

#[test]
fn id_to_string_agrees_with_the_real_pico_library() {
    // `z_id_to_string(const z_id_t*, z_owned_string_t*)` — the id is 16 bytes by
    // value-address, and the output is an owned string read back through each
    // library's OWN `z_string_data` / `z_string_len`. Reading wz's string with
    // pico's accessors (or the reverse) would be comparing two different
    // internal representations, which is not the property under test: the
    // property is that a pico PROGRAM, using pico's accessors on whichever
    // library it linked, sees the same characters.
    unsafe {
        let wz = open(wz_cdylib());
        let pico = open(pico_library());

        let cases: Vec<[u8; ID_SIZE]> = vec![
            [0u8; ID_SIZE],
            {
                let mut id = [0u8; ID_SIZE];
                id[0] = 0x01;
                id
            },
            {
                let mut id = [0u8; ID_SIZE];
                id[ID_SIZE - 1] = 0x80;
                id
            },
            [0xFF; ID_SIZE],
            {
                // An asymmetric id: any endianness or nibble-order slip shows.
                let mut id = [0u8; ID_SIZE];
                for (i, b) in id.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(17).wrapping_add(3);
                }
                id
            },
        ];

        for id in cases {
            let from_wz = render(&wz, &id);
            let from_pico = render(&pico, &id);
            assert_eq!(
                from_wz, from_pico,
                "z_id_to_string disagrees with upstream for id {id:02x?}"
            );
            assert_eq!(
                from_wz.len(),
                ID_SIZE * 2,
                "a zid renders as exactly 32 hex characters"
            );
        }

        // Non-vacuity: the comparison above would also pass if BOTH sides
        // rendered nothing. Pin one concrete value against the little-endian
        // reading, so an empty-output build fails here even if it fails
        // identically on both sides.
        let mut id = [0u8; ID_SIZE];
        id[0] = 0xAB;
        assert_eq!(
            render(&wz, &id),
            "000000000000000000000000000000ab",
            "byte 0 of the id must render LAST -- pico is little-endian here"
        );
    }
}

/// Call one library's `z_id_to_string` and read the result back through THAT
/// library's own string accessors.
///
/// # Safety
/// `lib` must export pico's string ABI.
unsafe fn render(lib: &Library, id: &[u8; ID_SIZE]) -> String {
    // `z_owned_string_t` is 32 B in pico's header; both implementations agree on
    // that (pinned by `wz-capi-pico`'s own ABI test), so a 32-byte zeroed buffer
    // is a valid out-parameter for either.
    let mut owned = [0u8; 32];
    let to_string: Symbol<unsafe extern "C" fn(*const u8, *mut u8) -> i8> = lib
        .get(b"z_id_to_string\0")
        .expect("library does not export z_id_to_string");
    let loan: Symbol<unsafe extern "C" fn(*const u8) -> *const u8> = lib
        .get(b"z_string_loan\0")
        .expect("library does not export z_string_loan");
    let data: Symbol<unsafe extern "C" fn(*const u8) -> *const u8> = lib
        .get(b"z_string_data\0")
        .expect("library does not export z_string_data");
    let len: Symbol<unsafe extern "C" fn(*const u8) -> usize> = lib
        .get(b"z_string_len\0")
        .expect("library does not export z_string_len");

    let rc = to_string(id.as_ptr(), owned.as_mut_ptr());
    assert_eq!(rc, 0, "z_id_to_string failed");
    let loaned = loan(owned.as_ptr());
    let ptr = data(loaned);
    let n = len(loaned);
    assert!(!ptr.is_null(), "z_string_data returned NULL");
    String::from_utf8(std::slice::from_raw_parts(ptr, n).to_vec()).expect("hex is UTF-8")
}

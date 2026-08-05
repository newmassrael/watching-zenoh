// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the DROP-IN census: every public symbol the real
//! `libzenohpico.so` defines must also be defined by wz's cdylib.
//!
//! ## Why a census, when a census is not a proof
//!
//! This workspace already records that a LINK census is not a behavioural proof
//! — a program that links can still answer differently, which is why the
//! compile-twice-and-diff differentials exist. The census answers the OTHER
//! question, and nothing else in the tree answers it: *which programs cannot
//! even be attempted?* A binary drop-in is a claim about the linker, and a
//! symbol the real library defines and wz does not is a program that fails at
//! link time — no behaviour to compare, no differential to write, and invisible
//! to every existing leg because those legs drive the exports wz happens to
//! have. That is precisely the bias `api-compat-pico`'s corpus rule exists to
//! avoid, applied to the symbol table instead of to the program list.
//!
//! So the two gates are complementary and neither subsumes the other: this file
//! bounds the SURFACE, `pico_c_examples_on_wz_capi_dropin.rs` and
//! `pico_pure_function_oracle.rs` bound the BEHAVIOUR.
//!
//! ## The reference is the built artifact, never a header
//!
//! The comparison reads the ELF `.dynsym` of both `.so` files directly rather
//! than parsing a header or shelling to `nm`. A header lists what upstream
//! DECLARES; a `.so` lists what it DEFINES, and those differ (pico's header
//! carries `Z_FEATURE`-gated prototypes whose bodies a given build omits). The
//! artifact is what a linker resolves against, so the artifact is the oracle.
//!
//! Parsing ELF here rather than running `nm` keeps the gate free of a binutils
//! prerequisite it would silently skip on, and makes the "what counts as a
//! public symbol" rule explicit and testable instead of an awk column.
//!
//! ## Scope of the claim
//!
//! Only GLOBAL, DEFINED symbols named `z_*` / `zp_* `/ `ze_*` count — pico's own
//! internal `_z_*` plane is not API, and neither is a symbol the reference
//! itself leaves undefined. wz exporting MORE than the reference is not a
//! finding: the north star is a composable superset, and the unstable-API and
//! wz-only transport families live there.

use std::collections::BTreeSet;
use std::path::Path;

use wz_integration_tests::common::{wz_capi_pico_cdylib, zenoh_pico_shared_library};

/// `SHT_DYNSYM`.
const SHT_DYNSYM: u32 = 11;
/// `STB_GLOBAL` / `STB_WEAK` — the binding classes a linker resolves against.
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
/// `SHN_UNDEF` — an entry the object references but does not define.
const SHN_UNDEF: u16 = 0;

/// Read a little-endian `u16` / `u32` / `u64` at `off`, or `None` past the end.
fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Every GLOBAL/WEAK, DEFINED dynamic symbol name in an ELF64 little-endian
/// shared object.
///
/// Panics rather than returning an error on a malformed input: the two inputs
/// are build products of this very tree, so a parse failure is a broken harness
/// and must not read as "no symbols missing".
fn defined_dynamic_symbols(path: &Path) -> BTreeSet<String> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(
        bytes.get(..4),
        Some(&[0x7f, b'E', b'L', b'F'][..]),
        "{} is not an ELF object",
        path.display()
    );
    assert_eq!(bytes[4], 2, "{}: ELF64 expected", path.display());
    assert_eq!(bytes[5], 1, "{}: little-endian expected", path.display());

    let shoff = u64_at(&bytes, 0x28).expect("e_shoff") as usize;
    let shentsize = u16_at(&bytes, 0x3a).expect("e_shentsize") as usize;
    let shnum = u16_at(&bytes, 0x3c).expect("e_shnum") as usize;
    assert_eq!(
        shentsize,
        64,
        "{}: ELF64 section header is 64 B",
        path.display()
    );

    let mut names = BTreeSet::new();
    let mut found_dynsym = false;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if u32_at(&bytes, sh + 0x04).expect("sh_type") != SHT_DYNSYM {
            continue;
        }
        found_dynsym = true;
        let sym_off = u64_at(&bytes, sh + 0x18).expect("sh_offset") as usize;
        let sym_size = u64_at(&bytes, sh + 0x20).expect("sh_size") as usize;
        let strtab_idx = u32_at(&bytes, sh + 0x28).expect("sh_link") as usize;
        let entsize = u64_at(&bytes, sh + 0x38).expect("sh_entsize") as usize;
        assert_eq!(entsize, 24, "{}: Elf64_Sym is 24 B", path.display());

        let str_sh = shoff + strtab_idx * shentsize;
        let str_off = u64_at(&bytes, str_sh + 0x18).expect("strtab sh_offset") as usize;
        let str_size = u64_at(&bytes, str_sh + 0x20).expect("strtab sh_size") as usize;
        let strtab = &bytes[str_off..str_off + str_size];

        for s in (0..sym_size / entsize).map(|n| sym_off + n * entsize) {
            let st_name = u32_at(&bytes, s).expect("st_name") as usize;
            let st_info = bytes[s + 4];
            let st_shndx = u16_at(&bytes, s + 6).expect("st_shndx");
            if st_shndx == SHN_UNDEF {
                continue;
            }
            let bind = st_info >> 4;
            if bind != STB_GLOBAL && bind != STB_WEAK {
                continue;
            }
            let end = strtab[st_name..]
                .iter()
                .position(|&c| c == 0)
                .expect("NUL-terminated strtab entry");
            let name = std::str::from_utf8(&strtab[st_name..st_name + end]).expect("utf8 symbol");
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
    }
    assert!(found_dynsym, "{}: no .dynsym section", path.display());
    names
}

/// Whether `name` is part of the PUBLIC zenoh-pico C API surface.
///
/// `_z_*` is upstream's internal plane and is not a drop-in obligation; a
/// leading underscore anywhere else is the same signal. Everything else in the
/// three API prefixes counts.
fn is_public_api(name: &str) -> bool {
    !name.starts_with('_')
        && (name.starts_with("z_") || name.starts_with("zp_") || name.starts_with("ze_"))
}

/// Public API symbols the REAL library defines and wz's cdylib does not.
fn missing_public_symbols() -> BTreeSet<String> {
    let wz: BTreeSet<String> = defined_dynamic_symbols(&wz_capi_pico_cdylib())
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();
    let reference: BTreeSet<String> = defined_dynamic_symbols(&zenoh_pico_shared_library())
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();
    assert!(
        reference.len() > 500,
        "the reference exported only {} public symbols — the oracle is not the \
         real zenoh-pico library, and a census against a stub reports green",
        reference.len()
    );
    reference.difference(&wz).cloned().collect()
}

/// THE GATE: wz's cdylib defines every public symbol the real library defines.
///
/// A failure prints the missing set in full rather than only its size, because
/// the size alone cannot be acted on and the set is the work list.
///
/// The claim is `partial`, not `full`: this bounds the SURFACE — which programs
/// can be attempted at all — and says nothing about whether wz answers the same
/// way. The behavioural half is `pico_c_examples_on_wz_capi_dropin.rs` and
/// `pico_pure_function_oracle.rs`.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "reads the CMake-built libzenohpico.so oracle; run by run-ci Layer E"]
fn wz_defines_every_public_symbol_the_real_pico_defines() {
    let missing = missing_public_symbols();
    assert!(
        missing.is_empty(),
        "wz's zenoh-pico drop-in is missing {} public symbol(s); a C program \
         naming any of them fails to LINK, so no behavioural leg can reach it:\n{}",
        missing.len(),
        missing
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The census's own positive control.
///
/// A parser that silently returned an empty set — a wrong section type, an
/// off-by-one in the header offsets, a filter that matched nothing — would make
/// the gate above pass unconditionally. This pins that both inputs parse to a
/// plausible surface AND that the two agree on symbols that certainly exist in
/// both, so an empty `missing` set means agreement rather than blindness.
///
/// It witnesses no atom of its own: it is the gate above's positive control,
/// and crediting it separately would count one claim twice.
// wz-proves: none -- positive control for the census gate, not an atom witness
#[test]
#[ignore = "reads the CMake-built libzenohpico.so oracle; run by run-ci Layer E"]
fn the_census_reads_both_libraries_rather_than_nothing() {
    let wz: BTreeSet<String> = defined_dynamic_symbols(&wz_capi_pico_cdylib())
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();
    let reference: BTreeSet<String> = defined_dynamic_symbols(&zenoh_pico_shared_library())
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();
    assert!(
        wz.len() > 400,
        "wz parsed to only {} public symbols — the parse, not the ABI, is what \
         this number is measuring",
        wz.len()
    );
    assert!(
        reference.len() > 500,
        "reference parsed to {}",
        reference.len()
    );
    for anchor in [
        "z_open",
        "z_close",
        "z_put",
        "z_declare_subscriber",
        "z_bytes_loan",
        "z_keyexpr_as_view_string",
    ] {
        assert!(
            wz.contains(anchor),
            "wz is missing the anchor symbol {anchor}, so the parse is wrong"
        );
        assert!(
            reference.contains(anchor),
            "the reference is missing the anchor symbol {anchor}, so the parse is wrong"
        );
    }
    // The internal plane must NOT leak into the census, or the gate would demand
    // wz reproduce upstream's private functions.
    assert!(
        !wz.iter().any(|n| n.starts_with('_')),
        "the public filter let an internal symbol through"
    );
}

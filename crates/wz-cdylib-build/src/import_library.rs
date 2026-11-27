// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The import libraries of the system DLLs a crate of a library's graph names by
//! `#[link(name = ...)]`, made by the build where no SDK is on the link.
//!
//! A crate that imports a system function by DLL name (`raw-dylib`, as `windows-sys` does) needs no
//! import library. One that names a library (`#[link(name = "bcrypt")]`) has the compiler hand the
//! linker `bcrypt.lib`, which only the Windows SDK ships, and the linker stops on a file it cannot
//! open. Where the link is the toolchain's own linker and Visual Studio is not on the machine, the
//! build writes each such library here: an archive of one short import entry per function the
//! graph calls, the form an import library of the SDK holds and the one `raw-dylib` makes, read
//! by the linker for the same `__imp_` symbols and the same DLL imports.

use std::fmt::Write as _;
use std::path::Path;

/// A function a system DLL exports, called with the system's convention (`extern "system"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import {
    /// The name the DLL exports it by.
    pub name: &'static str,
    /// The bytes of its arguments on an x86 stack, which x86's symbol of it carries (`_name@8`).
    pub stack_bytes: u32,
}

/// A system library a crate of the graph names, the DLL it stands for and what the graph calls
/// of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemLibrary {
    /// The name the crate gives (`#[link(name = "bcrypt")]`), whose `.lib` the linker opens.
    pub name: &'static str,
    /// The DLL the functions are imported from (`bcrypt.dll`).
    pub dll: &'static str,
    /// The functions.
    pub functions: &'static [Import],
}

/// The machine of a Windows target, as its COFF headers state it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    /// `x86_64`: `IMAGE_FILE_MACHINE_AMD64`.
    X64,
    /// `x86`: `IMAGE_FILE_MACHINE_I386`.
    X86,
    /// `aarch64`: `IMAGE_FILE_MACHINE_ARM64`.
    Arm64,
}

impl Machine {
    /// The machine of a target architecture (`CARGO_CFG_TARGET_ARCH`), `None` for one Windows has no
    /// import library of here.
    pub fn of_arch(arch: &str) -> Option<Self> {
        match arch {
            "x86_64" => Some(Self::X64),
            "x86" => Some(Self::X86),
            "aarch64" => Some(Self::Arm64),
            _ => None,
        }
    }

    /// The COFF header's machine field.
    pub fn coff(self) -> u16 {
        match self {
            Self::X64 => 0x8664,
            Self::X86 => 0x014C,
            Self::Arm64 => 0xAA64,
        }
    }

    /// The symbol a caller of `import` names: x86 decorates a `stdcall` name with an underscore and
    /// its argument bytes, the others take it as exported.
    pub fn symbol(self, import: &Import) -> String {
        match self {
            Self::X86 => format!("_{}@{}", import.name, import.stack_bytes),
            Self::X64 | Self::Arm64 => import.name.to_owned(),
        }
    }

    /// How the loader's name is read from the symbol (`IMPORT_OBJECT_NAME_TYPE`): as it is
    /// (`IMPORT_OBJECT_NAME`, 1), or on x86 without the decoration (`IMPORT_OBJECT_NAME_UNDECORATE`,
    /// 3), since the DLL exports the bare name.
    fn name_type(self) -> u16 {
        match self {
            Self::X86 => 3,
            Self::X64 | Self::Arm64 => 1,
        }
    }
}

/// The short import entry of the function whose symbol is `symbol` (`IMPORT_OBJECT_HEADER`, then
/// the symbol and the DLL's name, each ended by a zero): a code import with no ordinal.
fn short_import(machine: Machine, symbol: &str, dll: &str) -> Vec<u8> {
    let size_of_data = u32::try_from(symbol.len() + 1 + dll.len() + 1).expect("a short name");
    let mut out = Vec::with_capacity(20 + size_of_data as usize);
    out.extend_from_slice(&0u16.to_le_bytes()); // Sig1: IMAGE_FILE_MACHINE_UNKNOWN
    out.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Sig2
    out.extend_from_slice(&0u16.to_le_bytes()); // Version
    out.extend_from_slice(&machine.coff().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp: none, so the bytes repeat
    out.extend_from_slice(&size_of_data.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // OrdinalOrHint
                                                // Type (bits 0-1): IMPORT_OBJECT_CODE, 0; NameType (bits 2-4).
    out.extend_from_slice(&(machine.name_type() << 2).to_le_bytes());
    out.extend_from_slice(symbol.as_bytes());
    out.push(0);
    out.extend_from_slice(dll.as_bytes());
    out.push(0);
    out
}

/// An archive member's header: name, date, owner, group, mode and size, space-padded.
fn member_header(out: &mut Vec<u8>, name: &str, size: usize) {
    let mut text = String::with_capacity(60);
    writeln!(
        text,
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`",
        0, 0, 0, 644
    )
    .expect("a string");
    assert_eq!(text.len(), 60, "an archive member header is 60 bytes");
    out.extend_from_slice(text.as_bytes());
}

/// The import library of `functions` of `dll` for `machine`: an archive whose symbol table names,
/// for each function, its `__imp_` pointer and its call thunk, both in the function's member.
///
/// # Panics
/// If the DLL's name does not fit an archive member's name (15 bytes), or no function is given.
pub fn import_library(machine: Machine, dll: &str, functions: &[Import]) -> Vec<u8> {
    assert!(
        !functions.is_empty(),
        "an import library of {dll} with no function"
    );
    assert!(
        dll.len() < 16,
        "{dll}: a DLL name past 15 bytes needs the archive's name table"
    );
    let members: Vec<(String, Vec<u8>)> = functions
        .iter()
        .map(|import| {
            let symbol = machine.symbol(import);
            let data = short_import(machine, &symbol, dll);
            (symbol, data)
        })
        .collect();
    let names: Vec<(String, usize)> = members
        .iter()
        .enumerate()
        .flat_map(|(i, (symbol, _))| [(format!("__imp_{symbol}"), i), (symbol.clone(), i)])
        .collect();
    let table_size = 4 + 4 * names.len() + names.iter().map(|(n, _)| n.len() + 1).sum::<usize>();
    let mut offset = 8 + 60 + table_size + (table_size & 1);
    let mut member_offsets = Vec::with_capacity(members.len());
    for (_, data) in &members {
        member_offsets.push(offset);
        offset += 60 + data.len() + (data.len() & 1);
    }

    let mut out = Vec::with_capacity(offset);
    out.extend_from_slice(b"!<arch>\n");
    member_header(&mut out, "/", table_size);
    let count = u32::try_from(names.len()).expect("a small table");
    out.extend_from_slice(&count.to_be_bytes());
    for (_, member) in &names {
        let at = u32::try_from(member_offsets[*member]).expect("a small archive");
        out.extend_from_slice(&at.to_be_bytes());
    }
    for (name, _) in &names {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
    }
    if table_size & 1 == 1 {
        out.push(b'\n');
    }
    let member_name = format!("{dll}/");
    for (_, data) in &members {
        member_header(&mut out, &member_name, data.len());
        out.extend_from_slice(data);
        if data.len() & 1 == 1 {
            out.push(b'\n');
        }
    }
    debug_assert_eq!(out.len(), offset);
    out
}

/// Whether the linker cargo resolved (`RUSTC_LINKER`) is the toolchain's own: `rust-lld`, or LLVM's
/// `lld-link`, by the file name of the path given.
pub fn links_without_sdk(linker: &str) -> bool {
    // A Windows file name is told apart from another without its case, its extension too.
    let file = linker
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(linker)
        .to_ascii_lowercase();
    let stem = file.strip_suffix(".exe").unwrap_or(&file);
    stem == "rust-lld" || stem == "lld-link"
}

/// The link of a DLL on an MSVC target by the toolchain's own linker: the import library of each
/// of `libraries` written to the build's output directory and searched there, and the linker
/// told to take no library a directive names (`/NODEFAULTLIB`), so no SDK and no Visual Studio
/// library is on the link. Nothing is done for another target, or for the MSVC linker, which finds
/// the SDK's own libraries. Call it from the `fn main` of the DLL crate's `build.rs`.
///
/// `/NODEFAULTLIB` is a `cdylib` link argument: it suits a library without `std` only, which links
/// no C runtime; a build with `std` on the same linker would lose the C runtime's own libraries.
///
/// # Panics
/// On an MSVC target of an architecture `Machine` has no machine of, or when the libraries
/// cannot be written.
pub fn emit_link_without_sdk(libraries: &[SystemLibrary]) {
    for var in [
        "CARGO_CFG_TARGET_ENV",
        "CARGO_CFG_TARGET_ARCH",
        "RUSTC_LINKER",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let Ok(linker) = std::env::var("RUSTC_LINKER") else {
        return;
    };
    if !links_without_sdk(&linker) {
        return;
    }
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let machine = Machine::of_arch(&arch)
        .unwrap_or_else(|| panic!("wz-cdylib-build: no import library is made for {arch}"));
    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR for a build script");
    let dir = Path::new(&out_dir).join("system-import-libraries");
    std::fs::create_dir_all(&dir).expect("the build's output directory is writable");
    for library in libraries {
        let bytes = import_library(machine, library.dll, library.functions);
        std::fs::write(dir.join(format!("{}.lib", library.name)), bytes)
            .expect("the build's output directory is writable");
    }
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-cdylib-link-arg=/NODEFAULTLIB");
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: Import = Import {
        name: "SystemFunction036",
        stack_bytes: 8,
    };
    const GEN: Import = Import {
        name: "BCryptGenRandom",
        stack_bytes: 16,
    };

    /// One archive member: where its header starts, its header name and its data.
    type Member = (usize, String, Vec<u8>);
    /// One symbol of the archive's table: its name and the offset of the member holding it.
    type Symbol = (String, usize);

    /// The archive's members as (header name, data), and its symbol table as (name, offset).
    fn read(archive: &[u8]) -> (Vec<Member>, Vec<Symbol>) {
        assert_eq!(&archive[..8], b"!<arch>\n");
        let mut at = 8;
        let mut members = Vec::new();
        while at < archive.len() {
            let header = std::str::from_utf8(&archive[at..at + 60]).expect("an ASCII header");
            assert_eq!(&header[58..], "`\n", "the header's end mark");
            let name = header[..16].trim_end().to_owned();
            let size: usize = header[48..58].trim_end().parse().expect("a size");
            members.push((at, name, archive[at + 60..at + 60 + size].to_vec()));
            at += 60 + size + (size & 1);
        }
        assert_eq!(at, archive.len(), "the members fill the archive exactly");
        let table = &members[0].2;
        assert_eq!(members[0].1, "/", "the symbol table comes first");
        let count = u32::from_be_bytes(table[..4].try_into().unwrap()) as usize;
        let offsets: Vec<usize> = (0..count)
            .map(|i| u32::from_be_bytes(table[4 + 4 * i..8 + 4 * i].try_into().unwrap()) as usize)
            .collect();
        let names: Vec<String> = table[4 + 4 * count..]
            .split(|&b| b == 0)
            .take(count)
            .map(|n| String::from_utf8(n.to_vec()).unwrap())
            .collect();
        (members, names.into_iter().zip(offsets).collect())
    }

    /// The fields of a short import entry: (machine, name type, symbol, dll).
    fn entry(data: &[u8]) -> (u16, u16, String, String) {
        assert_eq!(
            &data[..4],
            &[0, 0, 0xFF, 0xFF],
            "a short import entry's signature"
        );
        let machine = u16::from_le_bytes([data[6], data[7]]);
        let size = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        assert_eq!(size, data.len() - 20, "SizeOfData counts the two names");
        let info = u16::from_le_bytes([data[18], data[19]]);
        assert_eq!(info & 3, 0, "a code import");
        let mut parts = data[20..].split(|&b| b == 0);
        let symbol = String::from_utf8(parts.next().unwrap().to_vec()).unwrap();
        let dll = String::from_utf8(parts.next().unwrap().to_vec()).unwrap();
        (machine, (info >> 2) & 7, symbol, dll)
    }

    /// Every symbol the linker looks for is in the table, and points at the member that imports it
    /// from the DLL by its own name, for the machine asked. Turned red by an offset that misses its
    /// member, a name type or machine of another width, or a missing `__imp_` name.
    #[test]
    fn the_x64_library_points_each_symbol_at_its_import() {
        let lib = import_library(Machine::X64, "bcrypt.dll", &[GEN, RANDOM]);
        let (members, table) = read(&lib);
        assert_eq!(members.len(), 3, "the table and one member per function");
        let names: Vec<&str> = table.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "__imp_BCryptGenRandom",
                "BCryptGenRandom",
                "__imp_SystemFunction036",
                "SystemFunction036"
            ]
        );
        for (name, offset) in &table {
            let member = members
                .iter()
                .find(|m| m.0 == *offset)
                .expect("an offset at a member header");
            assert_eq!(member.1, "bcrypt.dll/");
            let (machine, name_type, symbol, dll) = entry(&member.2);
            assert_eq!(
                (machine, name_type, dll.as_str()),
                (0x8664, 1, "bcrypt.dll")
            );
            assert_eq!(name.trim_start_matches("__imp_"), symbol);
        }
    }

    /// x86 names the decorated `stdcall` symbol and has the loader read it undecorated.
    #[test]
    fn the_x86_library_decorates_the_symbol_and_imports_the_bare_name() {
        let lib = import_library(Machine::X86, "advapi32.dll", &[RANDOM]);
        let (members, table) = read(&lib);
        let names: Vec<&str> = table.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["__imp__SystemFunction036@8", "_SystemFunction036@8"]
        );
        let (machine, name_type, symbol, dll) = entry(&members[1].2);
        assert_eq!(machine, 0x014C);
        assert_eq!(
            name_type, 3,
            "IMPORT_OBJECT_NAME_UNDECORATE: the DLL exports the bare name"
        );
        assert_eq!(
            (symbol.as_str(), dll.as_str()),
            ("_SystemFunction036@8", "advapi32.dll")
        );
    }

    /// The bytes depend on the input alone (no time is written), so a build repeats them.
    #[test]
    fn the_library_is_the_same_bytes_every_time() {
        let one = import_library(Machine::Arm64, "bcrypt.dll", &[GEN]);
        assert_eq!(one, import_library(Machine::Arm64, "bcrypt.dll", &[GEN]));
        assert_eq!(entry(&read(&one).0[1].2).0, 0xAA64);
    }

    #[test]
    fn a_dll_name_past_a_member_name_and_an_empty_library_are_refused() {
        let long = std::panic::catch_unwind(|| {
            import_library(Machine::X64, "a-very-long-name.dll", &[GEN])
        });
        assert!(long.is_err());
        let empty = std::panic::catch_unwind(|| import_library(Machine::X64, "bcrypt.dll", &[]));
        assert!(empty.is_err());
    }

    /// The toolchain's linker by any path, and not the MSVC linker or another.
    #[test]
    fn the_toolchains_linker_is_told_from_the_msvc_one() {
        for yes in [
            "rust-lld",
            "rust-lld.exe",
            "C:\\rust\\bin\\rust-lld.exe",
            "/usr/bin/lld-link",
            "LLD-LINK.EXE",
        ] {
            assert!(links_without_sdk(yes), "{yes}");
        }
        for no in [
            "link.exe",
            "link",
            "",
            "ld.lld",
            "C:\\VS\\bin\\link.exe",
            "lld",
        ] {
            assert!(!links_without_sdk(no), "{no}");
        }
        assert_eq!(Machine::of_arch("x86_64"), Some(Machine::X64));
        assert_eq!(Machine::of_arch("x86"), Some(Machine::X86));
        assert_eq!(Machine::of_arch("riscv64"), None);
    }
}

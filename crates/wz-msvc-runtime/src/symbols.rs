// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The C runtime's symbols, each an assembly label: a label is no item of the compiler's, so a
//! `cdylib` that links this crate exports none of them, where a `#[no_mangle]` function would be
//! exported and handed to every program that links the library's import library.
//!
//! In this crate's own test build the labels carry a `wzrt_` prefix: the test program links the C
//! runtime, whose symbols they would otherwise meet, and the tests call the labels by those names.

use core::arch::global_asm;

/// The symbol of the C name `$name`: x86 gives C names a leading underscore, x64 does not.
#[cfg(all(target_arch = "x86_64", not(test)))]
macro_rules! symbol {
    ($name:literal) => {
        $name
    };
}
#[cfg(all(target_arch = "x86_64", test))]
macro_rules! symbol {
    ($name:literal) => {
        concat!("wzrt_", $name)
    };
}
#[cfg(all(target_arch = "x86", not(test)))]
macro_rules! symbol {
    ($name:literal) => {
        concat!("_", $name)
    };
}
#[cfg(all(target_arch = "x86", test))]
macro_rules! symbol {
    ($name:literal) => {
        concat!("_wzrt_", $name)
    };
}

/// A label of the C name `$name` that jumps to `$target`, which takes its arguments where the
/// caller left them and returns to the caller itself.
macro_rules! jump_label {
    ($name:literal, $target:path) => {
        global_asm!(
            ".text",
            concat!(".globl ", symbol!($name)),
            ".p2align 4",
            concat!(symbol!($name), ":"),
            "jmp {target}",
            target = sym $target,
        );
    };
}

jump_label!("memcpy", crate::mem::memcpy);
jump_label!("memmove", crate::mem::memmove);
jump_label!("memset", crate::mem::memset);
jump_label!("memcmp", crate::mem::memcmp);
jump_label!("strlen", crate::mem::strlen);

#[cfg(target_arch = "x86")]
jump_label!("_aulldiv", crate::div64::aulldiv);
#[cfg(target_arch = "x86")]
jump_label!("_aullrem", crate::div64::aullrem);
#[cfg(target_arch = "x86")]
jump_label!("_alldiv", crate::div64::alldiv);
#[cfg(target_arch = "x86")]
jump_label!("_allrem", crate::div64::allrem);

// `_fltused`: the marker every object that uses floating point names, read by nothing.
global_asm!(
    ".data",
    concat!(".globl ", symbol!("_fltused")),
    ".p2align 2",
    concat!(symbol!("_fltused"), ":"),
    ".long 0",
    ".text",
);

// The language handler the prebuilt `core` and `alloc` name in their unwind tables. Nothing
// unwinds in a library that aborts on a panic, so a frame of theirs handles no exception:
// `ExceptionContinueSearch` (1). On x86 the caller pops its arguments.
global_asm!(
    ".text",
    concat!(".globl ", symbol!("__CxxFrameHandler3")),
    ".p2align 4",
    concat!(symbol!("__CxxFrameHandler3"), ":"),
    "mov eax, 1",
    "ret",
);

// The DLL's entry, which the linker names for a DLL: there is no C runtime to start, so every
// notice the loader gives (attach, detach) succeeds (`TRUE`).
#[cfg(target_arch = "x86_64")]
global_asm!(
    ".text",
    concat!(".globl ", symbol!("_DllMainCRTStartup")),
    ".p2align 4",
    concat!(symbol!("_DllMainCRTStartup"), ":"),
    "mov eax, 1",
    "ret",
);
// x86: `stdcall`, three arguments, so the decorated name and `ret 12`.
#[cfg(target_arch = "x86")]
global_asm!(
    ".text",
    concat!(".globl ", symbol!("_DllMainCRTStartup"), "@12"),
    ".p2align 4",
    concat!(symbol!("_DllMainCRTStartup"), "@12:"),
    "mov eax, 1",
    "ret 12",
);

// `__chkstk` on x64: touches each page from the caller's stack pointer down by `rax` bytes, in
// order, so the system's guard page grows the stack; `rsp` is left alone, the caller lowers it.
// Every register but the flags is kept.
#[cfg(target_arch = "x86_64")]
global_asm!(
    ".text",
    concat!(".globl ", symbol!("__chkstk")),
    ".p2align 4",
    concat!(symbol!("__chkstk"), ":"),
    "push rcx",
    "push rax",
    "cmp rax, 0x1000",
    "lea rcx, [rsp + 24]",
    "jb 3f",
    "2:",
    "sub rcx, 0x1000",
    "test qword ptr [rcx], rcx",
    "sub rax, 0x1000",
    "cmp rax, 0x1000",
    "ja 2b",
    "3:",
    "sub rcx, rax",
    "test qword ptr [rcx], rcx",
    "pop rax",
    "pop rcx",
    "ret",
);

// `_chkstk` on x86: the same probe, and it lowers `esp` by `eax` itself before it returns. Every
// register but `esp` and the flags is kept.
#[cfg(target_arch = "x86")]
global_asm!(
    ".text",
    concat!(".globl ", symbol!("_chkstk")),
    ".p2align 4",
    concat!(symbol!("_chkstk"), ":"),
    "push ecx",
    "cmp eax, 0x1000",
    "lea ecx, [esp + 8]",
    "jb 3f",
    "2:",
    "sub ecx, 0x1000",
    "test dword ptr [ecx], ecx",
    "sub eax, 0x1000",
    "cmp eax, 0x1000",
    "ja 2b",
    "3:",
    "sub ecx, eax",
    "test dword ptr [ecx], ecx",
    "lea eax, [esp + 4]",
    "mov esp, ecx",
    "mov ecx, dword ptr [eax - 4]",
    "push dword ptr [eax]",
    "sub eax, esp",
    "ret",
);

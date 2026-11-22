/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The unwind tables of the library without `std` on Linux, discarded at the link
 * (`crates/.cargo/capi-discard-unwind-tables.toml`). The library's own crates are built without
 * them (`.cargo/capi-nostd.toml`), but the prebuilt `core` and `alloc` carry theirs, and a
 * compiler flag does not reach a crate this build does not compile. Nothing reads them: the
 * library aborts on a panic and starts no unwind, a foreign unwind entering it already finds
 * frames without tables, and it links no backtrace. docs/c-abi-size-diet.md T7 holds the argument.
 *
 * INSERT keeps the linker's own script and puts this statement after `.text`, ahead of the
 * `.eh_frame` statement of that script, so every `.eh_frame` input section is matched here
 * first; with none left, the linker writes no `.eh_frame_hdr` either. GNU ld honours it, so the
 * configuration names GNU ld; lld builds `.eh_frame` from its input sections apart and keeps it
 * (measured with LLD 22.1.6), and mold takes no SECTIONS command and refuses the link.
 */
SECTIONS
{
  /DISCARD/ : { *(.eh_frame) *(.eh_frame.*) }
}
INSERT AFTER .text;

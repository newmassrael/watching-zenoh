/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The code a traced run of the perf matrix executed, laid out together ahead of the rest of the
 * library's text (`crates/.cargo/capi-run-text.toml`, docs/win-budget/rss.md section 5.4). A read
 * fault on the text maps every page of the 64 KiB window around it that the page cache holds, so a
 * run whose functions are spread over the text holds it resident whole however few bytes it runs;
 * with them together, the windows of the rest are never faulted.
 *
 * Everything below this comment is written by
 * `scripts/host-bench/perf_matrix.py run-text <lib-W> crates/wz-capi-pico/link/run-text.ld <profiles>`
 * from the callgrind profiles of a run with `--trace-text`: one line a function, its own section and
 * the one the compiler gives a function it judged cold, a Rust name's hash matched by any characters
 * so a line holds while the function's path does. A function no line names keeps the linker's own
 * order, and with no line the output section is empty and is not written, so the order changes where
 * the code lies and never what it is.
 *
 * INSERT keeps the linker's own script and puts this statement before `.text`, so these input
 * sections are matched here first and land in the same executable segment. GNU ld and lld take it;
 * mold refuses a SECTIONS command, and the library is linked by GNU ld
 * (`crates/.cargo/capi-discard-unwind-tables.toml`).
 */
SECTIONS
{
  .text.run :
  {
  }
}
INSERT BEFORE .text;

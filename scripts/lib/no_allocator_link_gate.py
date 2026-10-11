#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3285 (no register item) -- a final MCU image that claims to run without a
heap must LINK without an allocator, and the gate keeps that true.

## The claim and why a library test cannot carry it

The fixed-memory plan (S1 .. S9) takes every allocation out of the MCU session
layer one seam at a time. Each step has its own witness: a counting global
allocator on the host proves a window allocates zero times. That is a proof
about the code a test DRIVES. It says nothing about code the test does not
reach, and nothing about what a final binary LINKS. The claim that matters to a
board is the second one: this image carries no allocator, and nothing in it can
ask for one.

Two facts make the second claim checkable without running the image.

  1. A `#![no_std]` binary with no `#[global_allocator]` that reaches the
     `alloc` crate does not link, or links only an allocator it carries. So a
     clean image is one whose symbol table names no allocator at all.
  2. A crate that never writes `extern crate alloc` cannot name `alloc::`. So
     "the graph carries no alloc" is a property of the SOURCE of the crates
     the compiler was actually given, with the features it was actually given.

## What is proved: two halves, both must hold

HALF 1, the linked ELF (`arm-none-eabi-nm`). The image's symbol table, defined
or undefined, must contain NONE of:

  A  an allocator ENTRY POINT: `__rust_alloc`, `__rust_dealloc`,
     `__rust_realloc`, `__rust_alloc_zeroed`, `__rust_alloc_error_handler`,
     `__rust_no_alloc_shim_is_unstable`, any `__rdl_*` (the default allocator's
     shims) and any `__rg_*` (the shims `#[global_allocator]` generates);
  B  an allocator IMPLEMENTATION: any `impl GlobalAlloc` method, which names an
     image's own heap (`embedded_alloc::..::Heap`, a FreeRTOS or Zephyr bridge,
     a hand-written one);
  C  code of the `alloc` crate: `alloc::alloc::*` (`exchange_malloc`,
     `handle_alloc_error`), `alloc::raw_vec`, `alloc::vec`, `alloc::boxed`,
     `alloc::rc`, `alloc::sync`, `alloc::string`, `alloc::fmt`,
     `alloc::collections`, `alloc::borrow`, and any monomorphisation naming
     them (a `drop_glue::<Box<..>>` is alloc code even though the glue lives in
     `core`). `alloc` code cannot exist in a linked image without class A.

Class D is REPORTED, not judged: the C heap entry points of a kernel
(`pvPortMalloc`, `k_malloc`, `malloc`, ...). They are the kernel's own heap and
a FreeRTOS image takes task stacks from it whatever Rust does; the Rust-side
claim is about the Rust allocator. lwIP's own `mem_malloc` / `memp_malloc` are
its static `MEM_SIZE` pool, not a heap, and are not class D.

An image with NO symbols (stripped, or `nm` unreadable) is not "clean": the
gate refuses it (a population of zero is not a pass), and so does a toolchain
whose `nm` does not demangle the v0 Rust mangling (a mangled name matches no
pattern, so every image would read clean).

HALF 2, the crate graph. The gate asks cargo what it COMPILED for the target
(`--message-format=json`: one `compiler-artifact` per unit, with the features
that unit was built with and its crate root), walks each unit's module tree
from that root, and reports every ACTIVE `extern crate alloc`, naming the crate,
file and line, and the `cfg` that keeps it live. Not `cargo metadata`: its
feature set is the union across host and target and across dependency kinds, so
a build-dependency's features would read as the image's. Not a hand list of
crates: the population is whatever the build compiled, so a new dependency that
brings `alloc` back is named the day it lands. `cfg(test)` is false, and a
predicate the evaluator does not know FAILS the gate rather than guessing; the
custom cfgs a package's own build script emitted (`build-script-executed`) are
taken from cargo, so `armv8m` or `lwip_real_build` are measured, not assumed.

Only the crates of THIS repository (and the vendored SCE runtime, which is its
own) are judged. A third-party crate that declares `extern crate alloc` and
never uses it links nothing, and one that uses it shows in half 1; they are
listed in the report, not judged. (`zeroize` does it in the existing no-heap
registry probe, which links clean.) The two halves also catch what the other
cannot: an UNUSED `extern crate alloc` leaves the symbol table clean but is
named by half 2, and the toolchain's own refusal (rustc stops the build with
"no global memory allocator found" when a crate links `alloc` and the image
has no `#[global_allocator]`) does not say WHICH crate, which half 2 does.

## What the verdict is

An image is in the table below as `gated` (it must be clean: both halves) or
`pending` (it is not clean yet and the gate says exactly what stands in the
way). The table is checked both ways: a `pending` image that turns out clean
FAILS the gate until it is promoted to `gated`, the same bidirectional rule the
tree's other ratchets follow, so the day a real image becomes alloc-free the
proof starts guarding it. A `deploy/` image that has no row FAILS (the
population is derived from `deploy/**/Cargo.toml`, not listed).

Today the one gated image is `mcu-link-noalloc-probe` (the link tier on
`static-link-storage`, a socket out of a static pool, no session crate); it is
the positive control. Every shipped image is `pending`, and the report is the
worklist for the steps that remove their allocations.

## Modes

  --selftest            fixtures only; no toolchain.
  --population          static: the deploy/ population against the table, and
                        for a gated image its manifest and sources (no
                        `#[global_allocator]`, no `extern crate alloc`, no
                        allocator crate in its dependency list). No toolchain.
  --image NAME [--target T] [--elf FILE --units FILE]
                        build (or read the given build's output), judge, print
                        the report; exit 0 when the image is in the state its
                        row says.
  --census DIR          every image of the table, every target, one report file
                        each plus an index (never fails on a pending image).

Source-line attribution of each allocation call site comes from the ELF's own
line table (`--lines`, which builds with `debug = line-tables-only`: the code is
the same, only `.debug_line` is added). Every branch to an allocator operation
(`__rust_alloc` and its siblings, a `GlobalAlloc` method, `exchange_malloc`, a
kernel's `pvPortMalloc`) is read through its inline chain; the row is the first
line of the repository's code after the standard library's frames, and where the
chain ends inside the standard library (a `Vec::from_elem` that was not inlined)
the walk goes to that helper's callers. That is the S6/S9 worklist: one row per
source line that asks for memory.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# The table. `gated`: must be clean. `pending`: must NOT be clean (promote it
# when it is), and the report is its worklist. The population is derived from
# deploy/; this table only classifies it.
# ---------------------------------------------------------------------------

# lwip port directory (under crates/lwip-sys/port) per target, where the image
# builds lwIP; None where it has no C dependency.
V7M = "thumbv7m-none-eabi"
V6M = "thumbv6m-none-eabi"
V7EMHF = "thumbv7em-none-eabihf"


@dataclass(frozen=True)
class Build:
    """One way an image is built, as the Layer Q lane builds it."""

    target: str
    port: str | None = None
    features: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    label: str = ""


@dataclass(frozen=True)
class Image:
    manifest: str  # repo-relative Cargo.toml
    kind: str  # "bin" | "staticlib"
    artifact: str  # bin name, or the staticlib's package name
    status: str  # "gated" | "pending"
    builds: tuple[Build, ...]
    pending: str = ""  # why it is not clean yet (the steps that repay it)
    # False: the lane does not run the gate on it (the census does). A Zephyr
    # staticlib is built by `west` with values Kconfig passes in the build
    # environment; the census builds it with stand-ins for them.
    ci: bool = True


# What `west build` passes the Zephyr staticlibs from Kconfig. The census builds
# them with stand-in values: they set constants (a clock rate, an address) and
# decide nothing about what the crates allocate.
ZEPHYR_BUILD_VALUES: tuple[tuple[str, str], ...] = (
    ("WZ_TICKS_PER_SEC", "1000"),
    ("WZ_CORE_CLOCK_HZ", "350000000"),
    ("WZ_STATIC_IPV4", "192.0.2.10"),
    ("WZ_STATIC_NETMASK", "255.255.255.0"),
    ("WZ_STATIC_GATEWAY", "192.0.2.1"),
    ("WZ_REF_CLOCK_DIVIDER", "2"),
    ("WZ_LINK_WAIT_MS", "1000"),
)

FREERTOS_CFG = ("WZ_FREERTOS_CONFIG", "@deploy/mcu-freertos-demo")

IMAGES: dict[str, Image] = {
    "mcu-link-noalloc-probe": Image(
        "deploy/mcu-link-noalloc-probe/Cargo.toml",
        "bin",
        "mcu-link-noalloc-probe",
        "gated",
        (
            Build(V7M, "cross-test", label="mps2"),
            Build(V6M, "microbit-minimal", label="microbit"),
        ),
    ),
    "mcu-noheap-probe": Image(
        "deploy/mcu-noheap-probe/Cargo.toml",
        "bin",
        "mcu-noheap-probe",
        "gated",
        (Build(V7M, label="mps2"), Build(V6M, label="microbit")),
    ),
    "mcu-session-acceptor": Image(
        "deploy/mcu-session-acceptor/Cargo.toml",
        "bin",
        "mcu-session-acceptor",
        "pending",
        (
            Build(V7M, "cross-test", label="mps2"),
            Build(
                V6M,
                "microbit-minimal",
                ("buffer-pool-session-rx-slim",),
                label="microbit-slim",
            ),
        ),
        "the session shell (Rc/RefCell shells, the pump's record Vec, spawn_local)"
        " and the e2e library still allocate: S6 and S8",
    ),
    "mcu-admin-node": Image(
        "deploy/mcu-admin-node/Cargo.toml",
        "bin",
        "mcu-admin-node",
        "pending",
        (Build(V7M, "cross-test", label="mps2"),),
        "the admin node shell, the observer tables and the JSON replies: S6, S9",
    ),
    "mcu-multicast-e2e": Image(
        "deploy/mcu-multicast-e2e/Cargo.toml",
        "bin",
        "mcu-multicast-e2e",
        "pending",
        (Build(V7M, "cross-test", label="mps2"),),
        "the multicast drive loop (boxed TX items, the reply queue) and the"
        " session shell: S6",
    ),
    "mcu-freertos-demo": Image(
        "deploy/mcu-freertos-demo/Cargo.toml",
        "bin",
        "mcu-freertos-demo",
        "pending",
        (Build(V7M, "cross-test", env=(FREERTOS_CFG,), label="mps2"),),
        "FreeRTOS heap_4 backs a Rust allocator; the session shell allocates: S6",
    ),
    "mcu-freertos-two-session": Image(
        "deploy/mcu-freertos-demo/Cargo.toml",
        "bin",
        "mcu-freertos-two-session",
        "pending",
        (
            Build(
                V7M,
                "cross-test-mcast",
                ("two-session",),
                env=(FREERTOS_CFG,),
                label="mps2",
            ),
        ),
        "two sessions on one local set: the shells, the multicast drive loop and"
        " the FreeRTOS allocator bridge: S6",
    ),
    "mcu-qemu-demo": Image(
        "deploy/mcu-qemu-demo/Cargo.toml",
        "bin",
        "mcu-qemu-demo",
        "pending",
        (Build(V7M, "cross-test", label="mps2"), Build(V6M, "microbit-minimal", label="microbit")),
        "the demo opens its socket with the heap constructor and spawns on the"
        " heap-backed cooperative runtime: S6, S7 wiring",
    ),
    "zephyr-admin-node": Image(
        "deploy/zephyr-admin-node/rust/Cargo.toml",
        "staticlib",
        "wz-zephyr-admin-node",
        "pending",
        (
            Build(
                V7EMHF,
                "@deploy/zephyr-admin-node/lwip-port",
                ("net-lwip-mac", "mac-cyt4bf"),
                env=ZEPHYR_BUILD_VALUES,
                label="cyt4bf-lwip",
            ),
        ),
        "the Zephyr allocator bridge, the node shell (Box<MacPort>, Vec, Rc) and"
        " the admin node: S6, S9",
        ci=False,
    ),
    "zephyr-app": Image(
        "deploy/zephyr-app/rust/Cargo.toml",
        "staticlib",
        "wz-zephyr-app",
        "pending",
        (Build(V7M, env=ZEPHYR_BUILD_VALUES, label="qemu_cortex_m3"),),
        "the Zephyr cooperative profile image allocates through the Zephyr heap",
        ci=False,
    ),
}

# ---------------------------------------------------------------------------
# cfg evaluation
# ---------------------------------------------------------------------------


class UnknownCfg(Exception):
    """A cfg predicate the evaluator has no value for."""


def _tokenise_cfg(text: str) -> list[str]:
    return re.findall(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_]*|[(),=]', text)


def eval_cfg(
    expr: str, features: set[str], target: str, build_cfgs: set[str] | None = None
) -> bool:
    """Evaluate the inside of `cfg(...)`. Raises UnknownCfg on a predicate with
    no value here, so a gate never decides on a guess.

    `build_cfgs` is what the package's own build script emitted
    (`cargo:rustc-cfg=..`, reported by cargo as `name` or `name="value"`), or
    None for a package that has no build script. A package that has one is the
    only authority on its own custom cfgs, so a predicate this table does not
    know is false there when the script did not emit it, and an error where
    there is no script to ask."""
    toks = _tokenise_cfg(expr)
    pos = 0

    def peek() -> str | None:
        return toks[pos] if pos < len(toks) else None

    def take(want: str | None = None) -> str:
        nonlocal pos
        tok = toks[pos]
        if want is not None and tok != want:
            raise UnknownCfg(f"expected {want!r} in cfg({expr})")
        pos += 1
        return tok

    def pred() -> bool:
        name = take()
        if name in ("all", "any", "not"):
            take("(")
            vals: list[bool] = []
            while peek() != ")":
                vals.append(pred())
                if peek() == ",":
                    take(",")
            take(")")
            if name == "all":
                return all(vals)
            if name == "any":
                return any(vals)
            if len(vals) != 1:
                raise UnknownCfg(f"not() takes one argument in cfg({expr})")
            return not vals[0]
        if peek() == "=":
            take("=")
            return key_value(name, take().strip('"'))
        return flag(name)

    def key_value(key: str, value: str) -> bool:
        if key == "feature":
            return value in features
        if key == "target_os":
            return value == "none"
        if key == "target_arch":
            return value == "arm"
        if key == "target_family":
            return False
        if key == "target_env" or key == "target_vendor":
            return value == ""
        if key == "target_pointer_width":
            return value == "32"
        if key == "target_endian":
            return value == "little"
        if key == "target_feature":
            # an M-profile thumb core; the x86 / wasm feature names crates test
            # for (`sse2`, `atomics`) are absent
            return value in ("thumb-mode", "mclass")
        if key == "target_has_atomic" or key == "target_has_atomic_load_store":
            if key == "target_has_atomic" and target.startswith("thumbv6m"):
                return False
            return value in ("8", "16", "32", "ptr")
        if build_cfgs is not None:
            return f'{key}="{value}"' in build_cfgs
        raise UnknownCfg(f"cfg predicate {key} = {value!r} has no value in this gate")

    def flag(name: str) -> bool:
        if name == "test" or name == "doc" or name == "debug_assertions":
            return False
        if name in ("unix", "windows", "miri", "loom"):
            return False
        if name == "panic" or name == "overflow_checks":
            return False
        if build_cfgs is not None:
            return name in build_cfgs
        raise UnknownCfg(f"cfg predicate {name} has no value in this gate")

    val = pred()
    if pos != len(toks):
        raise UnknownCfg(f"trailing tokens in cfg({expr})")
    return val


# ---------------------------------------------------------------------------
# Source half: the module tree of a unit, and its active `extern crate alloc`
# ---------------------------------------------------------------------------


def strip_comments(text: str) -> str:
    """Blank `//` and `/* */` comments (keeping line structure) and the bodies of
    string literals, so a `cfg(` or `extern crate` quoted in prose or in a
    string is not read as code. Raw strings are blanked too."""
    out: list[str] = []
    i, n = 0, len(text)
    attr = 0  # bracket depth inside an attribute: its strings are cfg values
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        m_attr = _ATTR_START.match(text, i) if c == "#" and not attr else None
        if m_attr:
            out.append(m_attr.group(0))
            attr = 1
            i = m_attr.end()
        elif two == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif two == "/*":
            depth = 1
            i += 2
            while i < n and depth:
                if text[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif text[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
        elif c == "r" and re.match(r'r#*"', text[i:]) and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = re.match(r'r(#*)"', text[i:])
            assert m is not None
            end = '"' + m.group(1)
            j = text.find(end, i + len(m.group(0)))
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", "", text[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            body = text[i : j + 1]
            # An attribute's strings are its values (`cfg(feature = "x")`,
            # `path = "m.rs"`) and the scan reads them; any other string is
            # blanked, so text quoted in code is not read as code.
            out.append(body if attr else '""' + re.sub(r"[^\n]", "", body))
            i = j + 1
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", text[i:]):
            m = re.match(r"'(\\.|[^\\'])'", text[i:])
            assert m is not None
            out.append("' '")
            i += len(m.group(0))
        else:
            if attr:
                attr += (c == "[") - (c == "]")
            out.append(c)
            i += 1
    return "".join(out)


_ATTR_START = re.compile(r"#\s*!?\s*\[")


def read_attr(text: str, i: int) -> tuple[str, bool, int]:
    """Read one attribute starting at `#`. Returns (inner text, is_inner, end)."""
    m = _ATTR_START.match(text, i)
    assert m is not None
    inner = "!" in text[i : m.end()]
    depth, j = 1, m.end()
    while j < len(text) and depth:
        if text[j] == "[":
            depth += 1
        elif text[j] == "]":
            depth -= 1
        j += 1
    return text[m.end() : j - 1].strip(), inner, j


def cfg_expr_of(attr: str) -> str | None:
    m = re.match(r"cfg\s*\((.*)\)\s*$", attr, re.S)
    return m.group(1) if m else None


# One item the scan reads: `extern crate alloc;`, or `mod name;` / `mod name {`.
_ITEM_RE = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?P<extern>extern\s+crate\s+alloc\b[^;]*;)"
    r"|mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<end>;|\{))"
)
_ITEM_KEYWORD_RE = re.compile(
    r"(?:pub\b|fn\b|impl\b|struct\b|enum\b|trait\b|union\b|const\b|static\b|use\b"
    r"|type\b|unsafe\b|macro_rules\b|extern\b|async\b)"
)


@dataclass
class AllocDecl:
    file: str
    line: int
    cfg: str  # the cfg text that keeps it live ("" when unconditional)


@dataclass
class ModuleScan:
    root: Path
    features: set[str]
    target: str
    build_cfgs: set[str] | None = None
    found: list[AllocDecl] = field(default_factory=list)
    visited: set[Path] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    def scan(self, path: Path, outer: list[str], rel_base: Path) -> None:
        path = path.resolve()
        if path in self.visited or not path.is_file():
            return
        self.visited.add(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = strip_comments(raw)
        line_of = _line_index(text)
        is_mod_rs = path.name in ("mod.rs", "lib.rs", "main.rs") or path == self.root.resolve()
        base_dir = path.parent if is_mod_rs else path.parent / path.stem

        i, n = 0, len(text)
        pending_cfg: list[str] = []
        pending_path: str | None = None
        block_stack: list[tuple[int, list[str]]] = []  # (depth inside the block, its cfgs)
        depth = 0
        file_cfg = list(outer)  # an inner `#![cfg(..)]` gates the whole file
        while i < n:
            c = text[i]
            if c == "#" and _ATTR_START.match(text, i):
                attr, inner, end = read_attr(text, i)
                expr = cfg_expr_of(attr)
                if inner:
                    if expr is not None:
                        file_cfg.append(expr)
                elif expr is not None:
                    pending_cfg.append(expr)
                else:
                    pm = re.match(r'path\s*=\s*"([^"]*)"', attr)
                    cm = re.match(r'cfg_attr\s*\((.*),\s*path\s*=\s*"([^"]*)"\s*\)$', attr, re.S)
                    if pm:
                        pending_path = pm.group(1)
                    elif cm and self._all_true([cm.group(1)]):
                        pending_path = cm.group(2)
                i = end
                continue
            if c == "{":
                depth += 1
                i += 1
                continue
            if c == "}":
                depth -= 1
                while block_stack and block_stack[-1][0] > depth:
                    block_stack.pop()
                i += 1
                continue
            if c in " \t\r\n":
                i += 1
                continue
            if i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_"):
                i += 1  # inside an identifier, not at the start of an item
                continue
            # What is live here: the file's cfgs, those of every enclosing
            # block, and the attributes of the item being read.
            cfgs = file_cfg + [e for _, block in block_stack for e in block] + pending_cfg
            m_item = _ITEM_RE.match(text, i)
            if m_item and m_item.group("extern") is not None:
                if self._all_true(cfgs):
                    self.found.append(AllocDecl(_rel(path, rel_base), line_of(i), " && ".join(cfgs)))
                i = m_item.end()
                pending_cfg, pending_path = [], None
                continue
            if m_item and m_item.group("end") == ";":
                name = m_item.group("name")
                if self._all_true(cfgs):
                    child = self._resolve_mod(base_dir, name, pending_path, path)
                    if child is not None:
                        self.scan(child, cfgs, rel_base)
                    else:
                        self.warnings.append(f"{_rel(path, rel_base)}:{line_of(i)}: `mod {name};` has no file")
                i = m_item.end()
                pending_cfg, pending_path = [], None
                continue
            if m_item or _ITEM_KEYWORD_RE.match(text, i):
                # An inline `mod x {` or a `{`-bodied item (`impl`, `fn`): its
                # cfgs hold for everything inside. Any other item is skipped to
                # its `;`, so its attributes do not leak onto the next one.
                j = m_item.end() - 1 if m_item else i
                while j < n and text[j] not in ";{":
                    j += 1
                if j < n and text[j] == "{":
                    depth += 1
                    block_stack.append((depth, list(pending_cfg)))
                j += 1
                i = j
                pending_cfg, pending_path = [], None
                continue
            i += 1

    def _all_true(self, cfgs: list[str]) -> bool:
        return all(eval_cfg(c, self.features, self.target, self.build_cfgs) for c in cfgs)

    @staticmethod
    def _resolve_mod(
        base_dir: Path, name: str, path_attr: str | None, here: Path
    ) -> Path | None:
        if path_attr:
            cand = (here.parent / path_attr).resolve()
            return cand if cand.is_file() else None
        for cand in (base_dir / f"{name}.rs", base_dir / name / "mod.rs"):
            if cand.is_file():
                return cand
        return None


def _line_index(text: str):
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())

    def line_of(offset: int) -> int:
        lo, hi = 0, len(starts)
        while lo < hi - 1:
            mid = (lo + hi) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid
        return lo + 1

    return line_of


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def scan_unit(
    package: str,
    src_path: Path,
    features: set[str],
    target: str,
    repo: Path,
    build_cfgs: set[str] | None = None,
) -> tuple[list[AllocDecl], list[str]]:
    """Active `extern crate alloc` of one compiled unit, from its crate root.

    A crate whose generated code lives under `out/<package>/` and is pulled in
    with `include!` is scanned over that directory too: those files carry their
    own `extern crate alloc` behind `cfg(feature = "alloc")`, which is the
    crate's own feature, so evaluating them with the unit's features is exact."""
    scan = ModuleScan(src_path, features, target, build_cfgs)
    scan.scan(src_path, [], repo)
    out_dir = repo / "out" / package
    if out_dir.is_dir():
        for extra in sorted(out_dir.glob("*.rs")):
            scan.scan(extra, [], repo)
    return scan.found, scan.warnings


# ---------------------------------------------------------------------------
# ELF half
# ---------------------------------------------------------------------------

REFUSAL = "no global memory allocator found"

ENTRY_RE = re.compile(
    r"(?:^|::)(?:__rust_(?:alloc|dealloc|realloc|alloc_zeroed|alloc_error_handler"
    r"|alloc_error_handler_should_panic|no_alloc_shim_is_unstable)"
    r"|__rdl_\w+|__rg_\w+)$"
)
IMPL_RE = re.compile(
    r"core::alloc::global::GlobalAlloc>::"
    # the heap crates themselves, so an `init` or a free-list walk that is not
    # a GlobalAlloc method (and an impl inlined away) still names its heap
    r"|(?<![\w])(?:embedded_alloc|linked_list_allocator|rlsf|talc|buddy_system_allocator)::"
)
ALLOC_CRATE_RE = re.compile(
    r"(?<![\w:])alloc::(?:alloc|raw_vec|vec|boxed|rc|sync|string|fmt|collections"
    r"|borrow|slice|str|ffi|task|ops)\b"
)
C_HEAP_RE = re.compile(
    r"^(?:pvPortMalloc|vPortFree|k_malloc|k_free|k_calloc|z_malloc|malloc|free|calloc|realloc"
    r"|_malloc_r|_free_r|_realloc_r|_calloc_r)$"
)
# The entries a call site is looked for at. CALL_TARGET_RE: what asks for
# memory (the Rust allocator's operations, an impl's methods, `exchange_malloc`
# which `Box::new` calls, and the C heap's, via C_HEAP_RE). FREE_RE: what gives
# it back, which is counted and not attributed.
FREE_RE = re.compile(
    r"(?:^|::)__rust_dealloc$|core::alloc::global::GlobalAlloc>::dealloc$"
    r"|(?:^|::)box_free$|^(?:vPortFree|k_free|free|_free_r)$"
)
CALL_TARGET_RE = re.compile(
    r"(?:^|::)__rust_(?:alloc|realloc|alloc_zeroed)$"
    r"|core::alloc::global::GlobalAlloc>::(?:alloc|alloc_zeroed|realloc)$"
    r"|(?:^|::)exchange_malloc$"
)


@dataclass
class Sym:
    addr: int | None
    size: int
    kind: str
    mangled: str
    name: str


def find_tool(env_var: str, candidates: tuple[str, ...]) -> str | None:
    if os.environ.get(env_var):
        return os.environ[env_var]
    for cand in candidates:
        if shutil.which(cand):
            return cand
    return None


def parse_nm(mangled_text: str, demangled_text: str) -> list[Sym]:
    """Zip the mangled and the demangled `nm -S -p` listings (same order)."""
    syms: list[Sym] = []
    mlines = [l for l in mangled_text.splitlines() if l.strip()]
    dlines = [l for l in demangled_text.splitlines() if l.strip()]
    if len(mlines) != len(dlines):
        raise ValueError(
            f"nm listings differ in length ({len(mlines)} mangled, {len(dlines)} demangled)"
        )
    for m, d in zip(mlines, dlines):
        pm = re.match(r"^\s*([0-9a-fA-F]+)?\s+(?:([0-9a-fA-F]+)\s+)?([A-Za-z?-])\s+(.*)$", m)
        pd = re.match(r"^\s*([0-9a-fA-F]+)?\s+(?:([0-9a-fA-F]+)\s+)?([A-Za-z?-])\s+(.*)$", d)
        if not pm or not pd:
            continue
        addr = int(pm.group(1), 16) if pm.group(1) else None
        size = int(pm.group(2), 16) if pm.group(2) else 0
        syms.append(Sym(addr, size, pm.group(3), pm.group(4), pd.group(4)))
    return syms


@dataclass
class ElfVerdict:
    entry: list[Sym]
    impl: list[Sym]
    alloc_code: list[Sym]
    c_heap: list[Sym]
    total: int

    @property
    def clean(self) -> bool:
        return not (self.entry or self.impl or self.alloc_code)


def classify(syms: list[Sym]) -> ElfVerdict:
    """Classes A, B, C (judged) and D (reported). Refuses an unusable table."""
    real = [s for s in syms if s.kind not in ("a", "A", "-")]
    if not real:
        raise ValueError("the symbol table is empty (a stripped image proves nothing)")
    undemangled = [s for s in real if s.name.startswith("_R") and s.name == s.mangled]
    if undemangled:
        raise ValueError(
            f"nm did not demangle {len(undemangled)} Rust v0 symbols (e.g. {undemangled[0].name}): "
            "use binutils with the Rust demangler, or the gate would read every image as clean"
        )
    entry, impl, code, cheap = [], [], [], []
    for s in real:
        if ENTRY_RE.search(s.name):
            entry.append(s)
        elif IMPL_RE.search(s.name):
            impl.append(s)
        elif ALLOC_CRATE_RE.search(s.name):
            code.append(s)
        if C_HEAP_RE.match(s.name):
            cheap.append(s)
    return ElfVerdict(entry, impl, code, cheap, len(real))


# --- call sites -------------------------------------------------------------

_BRANCH_RE = re.compile(r"^\s*([0-9a-f]+):\s+(b[a-z]*(?:\.[nw])?)\s+([0-9a-f]+)\s+<")


def parse_branches(objdump_text: str):
    """(address, target) of every direct branch in a `objdump -d` listing."""
    for line in objdump_text.splitlines():
        m = _BRANCH_RE.match(line)
        if m and m.group(2) not in ("bkpt", "bic", "bics", "bfc", "bfi", "bx", "blx"):
            yield int(m.group(1), 16), int(m.group(3), 16)


def parse_addr2line(text: str) -> dict[int, list[tuple[str, str, int]]]:
    """`addr2line -a -i -f -C` output -> address -> frames (function, file, line),
    innermost first."""
    result: dict[int, list[tuple[str, str, int]]] = {}
    cur: int | None = None
    pending_fn: str | None = None
    for line in text.splitlines():
        if re.match(r"^0x[0-9a-f]+$", line):
            cur = int(line, 16)
            result[cur] = []
            pending_fn = None
        elif cur is not None:
            if pending_fn is None:
                pending_fn = line
            else:
                m = re.match(r"^(.*):(\d+|\?)(?: \(discriminator \d+\))?$", line)
                file_, ln = (m.group(1), m.group(2)) if m else (line, "?")
                result[cur].append((pending_fn, file_, int(ln) if ln.isdigit() else 0))
                pending_fn = None
    return result


def crate_of_path(path: str, repo: Path) -> tuple[str, str]:
    """(crate, repo-relative-or-label path) for a source path in a line table."""
    if "-cgu." in path:
        # an LTO codegen unit's own name where DWARF has no source file
        return "?", "(compiler-generated, no source file)"
    p = path
    for prefix in (str(repo) + "/", "/wz/"):
        if p.startswith(prefix):
            p = os.path.normpath(p[len(prefix):])
            break
    m = re.match(r"^/?rustc/[0-9a-f]+/library/([^/]+)/", path)
    if m:
        return f"rust-std:{m.group(1)}", path.split("/library/", 1)[1]
    m = re.search(r"registry/src/[^/]+/([^/]+)/(.*)$", path)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^crates/([^/]+)/", p)
    if m:
        return m.group(1), p
    m = re.match(r"^out/([^/]+)/", p)
    if m:
        return m.group(1), p
    m = re.match(r"^deploy/([^/]+)/", p)
    if m:
        return m.group(1), p
    m = re.match(r"^vendor/sce/backends/rust/([^/]+)/", p)
    if m:
        return m.group(1), p
    m = re.match(r"^vendor/(freertos-kernel|lwip)/", p)
    if m:
        return m.group(1), p
    return "?", p


@dataclass
class CallSite:
    crate: str
    where: str  # file:line
    kinds: dict[str, int]  # target kind -> call instructions


_SHIM_FRAME_RE = re.compile(r"(?:^|::)(?:__rg_\w+|__rust_\w+|__rdl_\w+)$|GlobalAlloc>::")


def call_sites(
    syms: list[Sym], branches: list[tuple[int, int]]
) -> tuple[list[int], dict[int, str], int]:
    """Addresses of branches to an allocation entry, which entry each reaches,
    and how many branches go to a FREE (counted, not attributed: a drop glue's
    callers fan out through every owner of the type, and the line that asks for
    memory is what a worklist needs)."""
    entries: dict[int, str] = {}
    frees: set[int] = set()
    shims: list[tuple[int, int]] = []  # the allocator's own functions
    for s in syms:
        if s.addr is None or s.kind not in ("t", "T", "w", "W"):
            continue
        if FREE_RE.search(s.name):
            frees.add(s.addr & ~1)
        elif CALL_TARGET_RE.search(s.name) or C_HEAP_RE.match(s.name):
            entries[s.addr & ~1] = s.name
        if ENTRY_RE.search(s.name) or IMPL_RE.search(s.name):
            shims.append((s.addr & ~1, (s.addr & ~1) + max(s.size, 2)))
    hits: list[int] = []
    kinds: dict[int, str] = {}
    free_count = 0
    for at, target in branches:
        if any(lo <= at < hi for lo, hi in shims):
            continue
        if (target & ~1) in entries:
            hits.append(at)
            kinds[at] = entries[target & ~1]
        elif (target & ~1) in frees:
            free_count += 1
    return hits, kinds, free_count


def pick_site(
    frames: list[tuple[str, str, int]], repo: Path, after_std: bool = True
) -> tuple[str, str] | None:
    """The source line that asked for memory, out of one branch's inline chain
    (innermost frame first): the first frame that is neither the Rust standard
    library nor an allocator shim, taken AFTER the standard library's frames.

    The frame before them is the allocator's own: `#[global_allocator]`
    generates `__rg_alloc` and friends at its declaration, so that line would
    otherwise be where every allocation in the image is charged. None when the
    chain ends inside the standard library (a generic helper such as
    `Vec::from_elem` that was not inlined into its caller). `after_std` is False
    for the branch that CALLS such a helper: there is no allocator frame in its
    chain, so the first line of the user's own code is the answer."""
    seen_std = not after_std
    for fn, file_, line in frames:
        crate, rel = crate_of_path(file_, repo)
        if crate.startswith("rust-std:") or _SHIM_FRAME_RE.search(fn):
            seen_std = True
            continue
        if seen_std:
            return crate, f"{rel}:{line}"
    return None


class FuncIndex:
    """Which function a code address is in, from the symbol table's sizes."""

    def __init__(self, syms: list[Sym]) -> None:
        rows = sorted(
            (s.addr & ~1, (s.addr & ~1) + max(s.size, 2), s.name)
            for s in syms
            if s.addr is not None and s.kind in ("t", "T", "w", "W")
        )
        self._starts = [r[0] for r in rows]
        self._rows = rows

    def containing(self, addr: int) -> tuple[int, int, str] | None:
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0 and self._rows[i][0] <= addr < self._rows[i][1]:
            return self._rows[i]
        return None


def attribute_sites(
    hits: list[int],
    kinds: dict[int, str],
    resolve,
    funcs: FuncIndex,
    callers_of: dict[int, list[int]],
    repo: Path,
    depth: int = 4,
) -> list[CallSite]:
    """One row per source line that asks for memory.

    A branch to the allocator is read through the ELF's line table
    (`resolve`: addresses -> inline chains). Where the chain ends inside the
    standard library, the allocation is in a generic helper that was not
    inlined, so the walk goes up to that function's callers (`callers_of`) and
    reads theirs, up to `depth` levels, and the row names the helper it went
    through."""
    grouped: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def record(site: tuple[str, str], kind: str, via: list[str]) -> None:
        where = site[1] + (f"  via {via[-1][:80]}" if via else "")
        short = kind.split("::")[-1] if "::" in kind else kind
        grouped[(site[0], where)][short] += 1

    level: list[tuple[int, str, list[str]]] = [(at, kinds[at], []) for at in hits]
    for d in range(depth + 1):
        if not level:
            break
        chains = resolve(sorted({at for at, _, _ in level}))
        nxt: list[tuple[int, str, list[str]]] = []
        for at, kind, via in level:
            site = pick_site(chains.get(at, []), repo, after_std=(d == 0))
            if site is not None:
                record(site, kind, via)
                continue
            fn = funcs.containing(at)
            callers = callers_of.get(fn[0], []) if fn else []
            if d < depth and callers:
                nxt.extend((c, kind, via + [fn[2]]) for c in callers)
            else:
                record(("?", f"(no caller line: in {fn[2][:80] if fn else '?'})"), kind, via)
        level = nxt
    return [CallSite(c, w, dict(k)) for (c, w), k in sorted(grouped.items())]


# ---------------------------------------------------------------------------
# Build driver
# ---------------------------------------------------------------------------


@dataclass
class Unit:
    package: str
    version: str
    src_path: Path
    features: set[str]
    filename: str
    build_cfgs: set[str] | None = None  # None: the package has no build script


def cargo_units(stdout: str, target: str) -> tuple[list[Unit], str | None, list[str]]:
    """Units compiled FOR the target, the bin's path if any, and the staticlibs."""
    units: list[Unit] = []
    executable: str | None = None
    messages: list[dict] = []
    for line in stdout.splitlines():
        if not line.startswith("{"):
            continue
        try:
            messages.append(json.loads(line))
        except ValueError:
            continue
    # What each package's build script emitted (`cargo:rustc-cfg=..`).
    emitted: dict[str, set[str]] = {}
    for msg in messages:
        if msg.get("reason") == "build-script-executed":
            emitted.setdefault(msg["package_id"], set()).update(msg.get("cfgs", []))
    for msg in messages:
        if msg.get("reason") != "compiler-artifact":
            continue
        kinds = msg["target"].get("kind", [])
        if "custom-build" in kinds or "proc-macro" in kinds:
            continue
        filenames = msg.get("filenames", [])
        if not filenames or f"/{target}/" not in filenames[0]:
            continue
        name, version = _pkg_name_version(msg["package_id"])
        units.append(
            Unit(
                name,
                version,
                Path(msg["target"]["src_path"]),
                set(msg.get("features", [])),
                filenames[0],
                emitted.get(msg["package_id"]),
            )
        )
        if msg.get("executable"):
            executable = msg["executable"]
    return units, executable, []


def _pkg_name_version(pkg_id: str) -> tuple[str, str]:
    """Name and version out of a cargo package id, in either of its spellings:
    `<source>#<name>@<version>` / `<source>#<version>` (the name is then the
    last path component of the source), and the older `<name> <version> (<source>)`."""
    m = re.match(r"^(\S+) (\S+) \(", pkg_id)
    if m:
        return m.group(1), m.group(2)
    source, _, frag = pkg_id.partition("#")
    if "@" in frag:
        name, _, version = frag.partition("@")
        return name, version
    return source.rstrip("/").rsplit("/", 1)[-1], frag


def build_command(image: Image, build: Build, lines: bool) -> tuple[list[str], dict[str, str]]:
    env = dict(os.environ)
    if build.port:
        port = build.port
        if port.startswith("@"):
            env["WZ_LWIP_PORT"] = str(REPO_ROOT / port[1:])
        else:
            env["WZ_LWIP_PORT"] = str(REPO_ROOT / "crates/lwip-sys/port" / port)
    for key, value in build.env:
        env[key] = str(REPO_ROOT / value[1:]) if value.startswith("@") else value
    if lines:
        env["CARGO_PROFILE_RELEASE_DEBUG"] = "line-tables-only"
    cmd = [
        "cargo",
        "build",
        "--release",
        "--manifest-path",
        str(REPO_ROOT / image.manifest),
        "--target",
        build.target,
        "--message-format=json-render-diagnostics",
    ]
    if image.kind == "bin":
        cmd += ["--bin", image.artifact]
    else:
        cmd += ["--lib"]
    if build.features:
        cmd += ["--features", ",".join(build.features)]
    if env.get("WZ_NOALLOC_TARGET_DIR"):
        cmd += ["--target-dir", env["WZ_NOALLOC_TARGET_DIR"]]
    return cmd, env


# ---------------------------------------------------------------------------
# Judging one build
# ---------------------------------------------------------------------------


@dataclass
class Report:
    image: str
    label: str
    target: str
    status: str
    elf: ElfVerdict | None
    allocs: list[tuple[str, str, AllocDecl, bool]]  # (crate, version, decl, first party)
    sites: list[CallSite]
    warnings: list[str]
    problems: list[str]
    refused: str = ""  # the toolchain's own refusal, when the build would not link
    frees: int = 0  # branches to a free, counted and not attributed

    @property
    def first_party(self) -> list[tuple[str, str, AllocDecl, bool]]:
        """The crates of this repository (and the vendored SCE runtime): the
        ones whose `extern crate alloc` is judged. A third-party crate that
        declares it without using it links nothing, which the ELF half would
        show; one that uses it is caught there. They are listed, not judged."""
        return [a for a in self.allocs if a[3]]

    @property
    def clean(self) -> bool:
        return (
            not self.problems
            and not self.refused
            and self.elf is not None
            and self.elf.clean
            and not self.first_party
        )


def judge_units(
    units: list[Unit], target: str, repo: Path
) -> tuple[list[tuple[str, str, AllocDecl, bool]], list[str], list[str]]:
    found: list[tuple[str, str, AllocDecl, bool]] = []
    warnings: list[str] = []
    problems: list[str] = []
    seen: set[tuple[str, Path]] = set()
    for unit in units:
        key = (unit.package, unit.src_path)
        if key in seen:
            continue
        seen.add(key)
        try:
            decls, warns = scan_unit(
                unit.package, unit.src_path, unit.features, target, repo, unit.build_cfgs
            )
        except UnknownCfg as exc:
            problems.append(f"{unit.package}: {exc}")
            continue
        warnings.extend(f"{unit.package}: {w}" for w in warns)
        mine = _is_under(unit.src_path, repo)
        found.extend((unit.package, unit.version, d, mine) for d in decls)
    return found, warnings, problems


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


_REPO_CRATE_RE = re.compile(r"\b(wz_[a-z0-9_]+|mcu_[a-z0-9_]+|sce_[a-z0-9_]+)::")


def crates_named_in(rows: list[Sym]) -> Counter:
    """How many of these symbols name each crate of this repository in their
    demangled path: an `alloc::vec::Vec<wz_codecs::..>` is alloc code holding
    that crate's type. A reading aid for the report, not a verdict."""
    named: Counter = Counter()
    for s in rows:
        for crate in set(_REPO_CRATE_RE.findall(s.name)):
            named[crate.replace("_", "-")] += 1
    return named


def _alloc_lines(rows: list[tuple[str, str, AllocDecl, bool]]) -> list[str]:
    """One line per declaration; the generated files under out/<crate>/ (one
    per codec) collapse into one line, since they all hang on the same cfg."""
    by_crate: dict[tuple[str, str], list[AllocDecl]] = defaultdict(list)
    for crate, version, decl, _ in rows:
        by_crate[(crate, version)].append(decl)
    lines: list[str] = []
    for (crate, version), decls in sorted(by_crate.items()):
        label = crate if version == "0.1.0" else f"{crate} {version}"
        generated = [d for d in decls if d.file.startswith("out/")]
        for d in (d for d in decls if not d.file.startswith("out/")):
            cond = f"[cfg: {d.cfg}]" if d.cfg else "[unconditional]"
            lines.append(f"      {label}  {crate_of_path(d.file, REPO_ROOT)[1]}:{d.line}  {cond}")
        if generated:
            cond = f"[cfg: {generated[0].cfg}]" if generated[0].cfg else "[unconditional]"
            lines.append(f"      {label}  out/{crate}/*.rs ({len(generated)} generated files)  {cond}")
    return lines


def render(report: Report, verbose: bool = True) -> str:
    out: list[str] = []
    state = "CLEAN" if report.clean else "ALLOCATES"
    out.append(
        f"IMAGE {report.image} [{report.label}] {report.target}  status={report.status}  now={state}"
    )
    for p in report.problems:
        out.append(f"  PROBLEM {p}")
    if report.refused:
        out.append(f"  REFUSED by the toolchain: {report.refused}")
    if report.elf is not None:
        e = report.elf
        out.append(f"  elf: {e.total} symbols")
        for title, rows in (
            ("A allocator entry points", e.entry),
            ("B allocator implementations", e.impl),
            ("C alloc-crate code", e.alloc_code),
            ("D C heap (reported, not judged)", e.c_heap),
        ):
            out.append(f"  {title}: {len(rows)}")
            shown = rows if verbose else rows[:6]
            for s in shown:
                where = f"{s.addr:08x}" if s.addr is not None else "undefined"
                out.append(f"      {where} {s.size:6d} {s.kind} {s.name[:200]}")
            if len(rows) > len(shown):
                out.append(f"      ... {len(rows) - len(shown)} more")
            if rows is e.alloc_code and rows:
                named = crates_named_in(rows)
                out.append(
                    "      by the repository crate each symbol's type names: "
                    + ", ".join(f"{c} {n}" for c, n in named.most_common())
                )
    mine = report.first_party
    out.append(f"  crates of this repository that carry `extern crate alloc` in this build: {len({a[0] for a in mine})}")
    out.extend(_alloc_lines(mine))
    others = [a for a in report.allocs if not a[3]]
    out.append(f"  third-party crates that declare it (reported, judged by the ELF): {len({a[0] for a in others})}")
    out.extend(_alloc_lines(others))
    if report.sites:
        by_crate: dict[str, list[CallSite]] = defaultdict(list)
        for site in report.sites:
            by_crate[site.crate].append(site)
        total = sum(sum(s.kinds.values()) for s in report.sites)
        out.append(
            f"  allocation call sites (ELF line table): {total} branch(es) in {len(report.sites)} source line(s)"
            f"; {report.frees} branch(es) to a free are counted, not attributed"
        )
        for crate in sorted(by_crate):
            n = sum(sum(s.kinds.values()) for s in by_crate[crate])
            out.append(f"    {crate}: {n}")
            for s in by_crate[crate]:
                kinds = ", ".join(f"{k} x{v}" for k, v in sorted(s.kinds.items()))
                out.append(f"        {s.where}  ({kinds})")
    for w in report.warnings:
        out.append(f"  note: {w}")
    return "\n".join(out)


def judge_build(
    name: str, image: Image, build: Build, args: argparse.Namespace
) -> Report:
    nm = find_tool("NM", ("arm-none-eabi-nm", "llvm-nm"))
    objdump = find_tool("OBJDUMP", ("arm-none-eabi-objdump", "llvm-objdump"))
    addr2line = find_tool("ADDR2LINE", ("arm-none-eabi-addr2line", "llvm-addr2line"))
    problems: list[str] = []
    if nm is None:
        raise SystemExit("no_allocator_link_gate: no arm-none-eabi-nm or llvm-nm on PATH (cannot judge)")

    refused = ""
    if args.units:
        stdout = Path(args.units).read_text()
    else:
        cmd, env = build_command(image, build, bool(args.lines))
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            if REFUSAL in proc.stderr + proc.stdout:
                # rustc's own link check: a crate in the graph links `alloc` and
                # the image has no `#[global_allocator]`. That is this proof
                # holding, from the toolchain's side; what the toolchain does
                # not say is WHICH crate, which the source half still can.
                refused = REFUSAL
            else:
                sys.stderr.write(proc.stderr[-4000:])
                raise SystemExit(f"no_allocator_link_gate: {name} [{build.label}] does not build (rc={proc.returncode})")
        stdout = proc.stdout
    units, executable, _ = cargo_units(stdout, build.target)
    if refused:
        allocs, warnings, scan_problems = judge_units(units, build.target, REPO_ROOT)
        return Report(name, build.label, build.target, image.status, None, allocs, [], warnings, scan_problems, refused)
    if not units:
        problems.append("cargo reported no unit built for the target (a gate that sees no subject must not pass)")
    elf_path = args.elf or executable
    artifact: str | None = elf_path
    if image.kind == "staticlib":
        libs = [u.filename for u in units if u.filename.endswith(".a")]
        artifact = args.elf or (libs[-1] if libs else None)
    if not artifact or not Path(artifact).exists():
        raise SystemExit(f"no_allocator_link_gate: no linked artifact for {name} [{build.label}]")

    def run(*tool_args: str) -> str:
        proc = subprocess.run(list(tool_args), capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit(f"no_allocator_link_gate: {' '.join(tool_args[:2])} failed: {proc.stderr[-400:]}")
        return proc.stdout

    mangled = run(nm, "-S", "-p", artifact)
    demangled = run(nm, "-S", "-p", "-C", artifact)
    syms = parse_nm(mangled, demangled)
    try:
        elf = classify(syms)
    except ValueError as exc:
        problems.append(str(exc))
        elf = None

    sites: list[CallSite] = []
    frees = 0
    if elf is not None and not elf.clean and image.kind == "bin" and objdump and addr2line and args.lines:
        branches = list(parse_branches(run(objdump, "-d", "--no-show-raw-insn", artifact)))
        hits, kinds, frees = call_sites(syms, branches)
        callers_of: dict[int, list[int]] = defaultdict(list)
        for at, target in branches:
            callers_of[target & ~1].append(at)

        def resolve(addrs: list[int]) -> dict[int, list[tuple[str, str, int]]]:
            chains: dict[int, list[tuple[str, str, int]]] = {}
            for i in range(0, len(addrs), 400):
                chunk = addrs[i : i + 400]
                text = run(addr2line, "-a", "-i", "-f", "-C", "-e", artifact, *[hex(a) for a in chunk])
                chains.update(parse_addr2line(text))
            return chains

        sites = attribute_sites(hits, kinds, resolve, FuncIndex(syms), callers_of, REPO_ROOT)

    allocs, warnings, scan_problems = judge_units(units, build.target, REPO_ROOT)
    problems.extend(scan_problems)
    return Report(
        name, build.label, build.target, image.status, elf, allocs, sites, warnings, problems, frees=frees
    )


# ---------------------------------------------------------------------------
# The static population check
# ---------------------------------------------------------------------------

ALLOCATOR_DEPS = ("embedded-alloc", "linked_list_allocator", "linked-list-allocator", "talc", "buddy_system_allocator")


def deploy_manifests(root: Path) -> list[Path]:
    found = sorted(root.glob("deploy/*/Cargo.toml")) + sorted(root.glob("deploy/*/rust/Cargo.toml"))
    return found


def population_problems(root: Path, images: dict[str, Image]) -> list[str]:
    problems: list[str] = []
    manifests = {str(p.relative_to(root)) for p in deploy_manifests(root)}
    classified = {img.manifest for img in images.values()}
    for missing in sorted(manifests - classified):
        problems.append(
            f"{missing}: a deploy image with no row in the no-allocator gate's table "
            "(classify it gated or pending)"
        )
    for stale in sorted(classified - manifests):
        problems.append(f"{stale}: the table names a manifest that does not exist")
    for name, img in images.items():
        manifest = root / img.manifest
        if not manifest.is_file():
            continue
        text = manifest.read_text()
        if img.kind == "bin" and not re.search(rf'name\s*=\s*"{re.escape(img.artifact)}"', text):
            problems.append(f"{name}: {img.manifest} declares no `{img.artifact}`")
        if img.status not in ("gated", "pending"):
            problems.append(f"{name}: status {img.status!r} is neither gated nor pending")
        if img.status == "pending" and not img.pending:
            problems.append(f"{name}: a pending image states no reason")
        if img.status == "gated":
            deps = [d for d in ALLOCATOR_DEPS if re.search(rf"^\s*{re.escape(d)}\s*=", text, re.M)]
            if deps:
                problems.append(f"{name}: gated, but its manifest depends on an allocator crate: {', '.join(deps)}")
            src_dir = manifest.parent / "src"
            for rs in sorted(src_dir.rglob("*.rs")) if src_dir.is_dir() else []:
                body = strip_comments(rs.read_text(errors="replace"))
                if re.search(r"#\s*\[\s*global_allocator\s*\]", body):
                    problems.append(f"{name}: gated, but {rs.relative_to(root)} declares a #[global_allocator]")
                if re.search(r"extern\s+crate\s+alloc\b", body):
                    problems.append(f"{name}: gated, but {rs.relative_to(root)} writes `extern crate alloc`")
    return problems


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

CLEAN_NM = """\
00000100 00000010 T Reset
00000200 00000020 t _RNvCs1_5probe4main
20000000 00000004 b _RNvCs1_5probe5CLOCK
00000300 0000005c t _RNvCs2_7___rustc17rust_begin_unwind
00001000 000000dc T mem_malloc
00001100 00000028 T memp_malloc
"""
CLEAN_NM_C = """\
00000100 00000010 T Reset
00000200 00000020 t probe::main
20000000 00000004 b probe::CLOCK
00000300 0000005c t __rustc::rust_begin_unwind
00001000 000000dc T mem_malloc
00001100 00000028 T memp_malloc
"""
HEAP_NM = CLEAN_NM + "00000400 00000020 t _RNvCs3_5alloc5alloc15exchange_malloc\n"
HEAP_NM_C = CLEAN_NM_C + "00000400 00000020 t alloc::alloc::exchange_malloc\n"


def rep_pending_clean_for_index(elf: ElfVerdict) -> Report:
    return Report("clean-img", "mps2", V7M, "gated", elf, [], [], [], [])


def _selftest() -> int:
    failures: list[str] = []

    def check(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)

    # cfg evaluator
    feats = {"alloc", "x"}
    check(eval_cfg('feature = "alloc"', feats, V7M), "feature true")
    check(not eval_cfg('feature = "nope"', feats, V7M), "feature false")
    check(eval_cfg('any(not(feature = "static-link-storage"), test)', feats, V7M), "any/not with test false")
    check(not eval_cfg('any(feature = "static-link-storage", test)', feats, V7M), "any all false")
    check(eval_cfg('all(feature = "alloc", feature = "x")', feats, V7M), "all true")
    check(not eval_cfg("test", feats, V7M), "test is false")
    check(eval_cfg('target_has_atomic = "32"', feats, V7M), "v7m has cas")
    check(not eval_cfg('target_has_atomic = "32"', feats, V6M), "v6m has no cas")
    try:
        eval_cfg("some_new_cfg", feats, V7M)
        check(False, "unknown predicate must raise")
    except UnknownCfg:
        pass
    check(not eval_cfg('target_feature = "sse2"', feats, V7M), "an x86 target feature is false on a thumb core")
    # only this repository's crates are judged; a third-party declaration is listed
    decl = AllocDecl("src/lib.rs", 1, 'feature = "alloc"')
    elf_clean = ElfVerdict([], [], [], [], 10)
    rep_third = Report("i", "l", V7M, "gated", elf_clean, [("zeroize", "1", decl, False)], [], [], [])
    rep_mine = Report("i", "l", V7M, "gated", elf_clean, [("wz-x", "0", decl, True)], [], [], [])
    check(rep_third.clean and not rep_mine.clean, "a third-party declaration is not judged, a first-party one is")
    check("wz-x" in verdict(rep_mine)[1] and verdict(rep_mine)[0] == 1, "the verdict names the first-party crate")
    check(verdict(rep_third) == (0, "clean, as gated"), "a clean gated image passes")
    rep_refused = Report("i", "l", V7M, "gated", None, [("wz-x", "0", decl, True)], [], [], [], REFUSAL)
    check(not rep_refused.clean and verdict(rep_refused)[0] == 1, "a toolchain refusal is red for a gated image")
    check("wz-x" in verdict(rep_refused)[1], "and names the crate")
    check(verdict(replace(rep_refused, status="pending"))[0] == 0, "a refusal is what a pending image is expected to show")
    rep_sites = Report(
        "img", "mps2", V7M, "pending", ElfVerdict([], [], [Sym(1, 2, "t", "m", "alloc::vec::Vec<u8>")], [], 10),
        [("wz-x", "0", decl, True)], [CallSite("wz-x", "crates/wz-x/src/lib.rs:5", {"alloc": 2})], [], [], frees=3,
    )
    index = census_index([rep_sites, rep_pending_clean_for_index(elf_clean)])
    check("crates/wz-x/src/lib.rs:5" in index and "wz-x: 1 build(s)" in index, "the census index lists the worklist")
    check("ALLOCATES" in index and "CLEAN" in index, "the census index shows both states")
    rep_pending_clean = Report("i", "l", V7M, "pending", elf_clean, [], [], [], [])
    check(verdict(rep_pending_clean)[0] == 1, "a pending image that is clean must be promoted")
    # a package with a build script is the authority on its own custom cfgs
    check(eval_cfg("armv8m", feats, V7M, {"armv8m"}), "a cfg the build script emitted is true")
    check(not eval_cfg("armv8m", feats, V7M, set()), "one it did not emit is false")
    check(eval_cfg('foo = "bar"', feats, V7M, {'foo="bar"'}), "a key-value build cfg")
    msg_bs = json.dumps(
        {"reason": "build-script-executed", "package_id": "path+file:///r/crates/c#c@0.1.0", "cfgs": ["armv8m"]}
    )
    msg_art = json.dumps(
        {
            "reason": "compiler-artifact",
            "package_id": "path+file:///r/crates/c#c@0.1.0",
            "target": {"name": "c", "kind": ["lib"], "src_path": "/r/crates/c/src/lib.rs"},
            "features": [],
            "filenames": ["/r/target/thumbv7m-none-eabi/release/deps/libc.rlib"],
        }
    )
    bs_units, _, _ = cargo_units(msg_bs + "\n" + msg_art + "\n", V7M)
    check(bs_units and bs_units[0].build_cfgs == {"armv8m"}, f"build script cfgs reach the unit: {bs_units}")

    # comment / string stripping
    check("extern crate alloc" not in strip_comments("// extern crate alloc;\n/* extern crate alloc; */\nlet s = \"extern crate alloc;\";\n"), "comments and strings are blanked")

    # module tree scan over a temp crate
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "src"
        (src / "inner").mkdir(parents=True)
        (src / "lib.rs").write_text(
            "//! docs mention extern crate alloc;\n"
            "#![no_std]\n"
            '#[cfg(feature = "alloc")]\nextern crate alloc;\n'
            '#[cfg(test)]\nmod tests;\n'
            "mod always;\n"
            '#[cfg(feature = "gated")]\nmod gated;\n'
            'mod inline {\n    #[cfg(test)]\n    extern crate alloc;\n}\n'
        )
        (src / "tests.rs").write_text("extern crate alloc;\n")
        (src / "always.rs").write_text("mod deeper;\n")
        (src / "always").mkdir()
        (src / "always" / "deeper.rs").write_text("extern crate alloc;\n")
        (src / "gated.rs").write_text("extern crate alloc;\n")

        def names(fs: set[str]) -> list[str]:
            found, _ = scan_unit("tmpcrate", src / "lib.rs", fs, V7M, root)
            return sorted(f"{d.file}:{d.line}" for d in found)

        check(names(set()) == ["src/always/deeper.rs:1"], f"module scan without features: {names(set())}")
        check(
            names({"alloc", "gated"}) == ["src/always/deeper.rs:1", "src/gated.rs:1", "src/lib.rs:4"],
            f"module scan with features: {names({'alloc', 'gated'})}",
        )
        # an active crate-level inner cfg that is false hides the whole file
        (src / "always" / "deeper.rs").write_text('#![cfg(feature = "off")]\nextern crate alloc;\n')
        check(names(set()) == [], "inner cfg gates a file")

    # ELF classification
    clean = classify(parse_nm(CLEAN_NM, CLEAN_NM_C))
    check(clean.clean, "a clean table reads clean")
    check(not clean.c_heap, "lwIP mem_malloc is not class D")
    heap = classify(parse_nm(HEAP_NM, HEAP_NM_C))
    check(not heap.clean and len(heap.alloc_code) == 1, "an alloc symbol turns the verdict red (the mutant)")
    shim = classify(
        parse_nm(
            CLEAN_NM + "00000500 00000008 t _RNvCs3_7___rustc26___rust_alloc_error_handler\n",
            CLEAN_NM_C + "00000500 00000008 t __rustc::__rust_alloc_error_handler\n",
        )
    )
    check(len(shim.entry) == 1, "an entry point is class A")
    impl = classify(
        parse_nm(
            CLEAN_NM + "00000600 00000100 t _RNvXs_Hx\n",
            CLEAN_NM_C + "00000600 00000100 t <embedded_alloc::llff::Heap as core::alloc::global::GlobalAlloc>::alloc\n",
        )
    )
    check(len(impl.impl) == 1, "a GlobalAlloc impl is class B")
    heap_init = classify(
        parse_nm(
            CLEAN_NM + "00000610 00000100 t _RNvXs_Ix\n",
            CLEAN_NM_C + "00000610 00000100 t embedded_alloc::llff::Heap::init\n",
        )
    )
    check(len(heap_init.impl) == 1, "a heap crate's init is class B")
    glue = classify(
        parse_nm(
            CLEAN_NM + "00000700 00000020 t _RNvCs3_Gx\n",
            CLEAN_NM_C + "00000700 00000020 t core::ptr::drop_glue::<alloc::boxed::Box<u8>>\n",
        )
    )
    check(len(glue.alloc_code) == 1, "drop glue over a Box is alloc code")
    core_layout = classify(
        parse_nm(
            CLEAN_NM + "00000800 00000020 t _RNvCs3_Lx\n",
            CLEAN_NM_C + "00000800 00000020 t core::alloc::layout::Layout::from_size_align\n",
        )
    )
    check(core_layout.clean, "core::alloc::Layout is not the alloc crate")
    cheap = classify(
        parse_nm(CLEAN_NM + "00000900 00000040 T pvPortMalloc\n", CLEAN_NM_C + "00000900 00000040 T pvPortMalloc\n")
    )
    check(cheap.clean and len(cheap.c_heap) == 1, "the C heap is reported and not judged")
    try:
        classify([])
        check(False, "an empty table must be refused")
    except ValueError:
        pass
    try:
        classify(parse_nm("00000100 00000010 t _RNvCs1_5probe4main\n", "00000100 00000010 t _RNvCs1_5probe4main\n"))
        check(False, "an undemangled table must be refused")
    except ValueError:
        pass

    # call sites
    check(list(parse_branches("   640:\tbl\t400 <x>\n   650:\tb.w\t401 <x>\n   670:\tbx\tlr\n")) == [(0x640, 0x400), (0x650, 0x401)], "branches are parsed")
    hs = parse_nm(HEAP_NM, HEAP_NM_C)
    hits, kinds, nfree = call_sites(hs, [(0x640, 0x400), (0x650, 0x401), (0x660, 0x200)])
    check(hits == [0x640, 0x650] and nfree == 0, f"call sites found: {hits}")
    free_syms = hs + [Sym(0x500, 0x20, "t", "m", "<embedded_alloc::Heap as core::alloc::global::GlobalAlloc>::dealloc")]
    f_hits, _, f_count = call_sites(free_syms, [(0x640, 0x400), (0x680, 0x500), (0x690, 0x500)])
    check(f_hits == [0x640] and f_count == 2, f"a free is counted and not attributed: {f_hits} {f_count}")

    def chains_of(text: str):
        parsed = parse_addr2line(text)
        return lambda addrs: {a: parsed[a] for a in addrs if a in parsed}

    # an inline chain reads: the allocator's own frame, the standard library's,
    # then the line of code that asked for the memory
    chain_text = (
        "0x00000640\nmcu_x::main\n/wz/deploy/mcu-x/src/main.rs:66\n"
        "alloc::alloc::alloc\n/rustc/abc123/library/alloc/src/alloc.rs:100\n"
        "wz_link_lwip::bind\n/wz/crates/wz-link-lwip/src/lib.rs:797\n"
        "0x00000650\n__rg_alloc\n/wz/deploy/mcu-x/src/main.rs:66\n"
        "alloc::alloc::alloc\n/rustc/abc123/library/alloc/src/alloc.rs:100\n"
        "mcu_x::go\n/wz/deploy/mcu-x/src/main.rs:12\n"
    )
    rows = attribute_sites(hits, kinds, chains_of(chain_text), FuncIndex(hs), {}, REPO_ROOT)
    check(
        [(r.crate, r.where) for r in rows]
        == [("mcu-x", "deploy/mcu-x/src/main.rs:12"), ("wz-link-lwip", "crates/wz-link-lwip/src/lib.rs:797")],
        f"the allocator's frame is not the allocation site: {[(r.crate, r.where) for r in rows]}",
    )
    check(crate_of_path("/home/u/.cargo/registry/src/index.crates.io-1/heapless-0.8.0/src/vec.rs", REPO_ROOT)[0] == "heapless-0.8.0", "registry crate")
    check(crate_of_path("/wz/crates/wz-codecs/../../out/wz-codecs/join.rs", REPO_ROOT) == ("wz-codecs", "out/wz-codecs/join.rs"), "a path through .. is normalised")
    check(crate_of_path("/wz/vendor/freertos-kernel/tasks.c", REPO_ROOT)[0] == "freertos-kernel", "the vendored kernel is a crate of its own")
    check(crate_of_path("mcu_x.0123abcd-cgu.0", REPO_ROOT)[0] == "?", "a codegen-unit pseudo file is unresolved")
    # a generic helper that was not inlined: the chain ends in std, so the walk
    # goes to the helper's callers
    helper = [Sym(0x6F0, 0x40, "t", "m", "alloc::vec::from_elem::<u8>"), Sym(0x400, 0x20, "t", "m", "alloc::alloc::exchange_malloc")]
    helper_chain = (
        "0x00000700\nmcu_x::main\n/wz/deploy/mcu-x/src/main.rs:66\n"
        "alloc::alloc::alloc\n/rustc/abc123/library/alloc/src/alloc.rs:100\n"
        "from_elem<u8>\n/rustc/abc123/library/alloc/src/vec/mod.rs:3708\n"
        "0x00000900\nwz_x::fill\n/wz/crates/wz-x/src/lib.rs:5\n"
    )
    h_hits, h_kinds, _ = call_sites(helper, [(0x700, 0x400)])
    h_rows = attribute_sites(
        h_hits, h_kinds, chains_of(helper_chain), FuncIndex(helper), {0x6F0: [0x900]}, REPO_ROOT
    )
    check(
        [(r.crate, r.where.split("  via ")[0]) for r in h_rows] == [("wz-x", "crates/wz-x/src/lib.rs:5")]
        and "from_elem" in h_rows[0].where,
        f"a non-inlined helper is attributed to its caller: {[(r.crate, r.where) for r in h_rows]}",
    )
    none_rows = attribute_sites(h_hits, h_kinds, chains_of(helper_chain), FuncIndex(helper), {}, REPO_ROOT)
    check(none_rows and none_rows[0].crate == "?", "a helper nobody calls is reported unresolved, not dropped")
    # a branch inside an allocator shim is the shim, not an allocation site
    shim_syms = [Sym(0x100, 0x20, "t", "m", "__rustc::__rust_realloc"), Sym(0x300, 0x10, "t", "m", "<embedded_alloc::Heap as core::alloc::global::GlobalAlloc>::alloc")]
    shim_hits, _, _ = call_sites(shim_syms, [(0x110, 0x300), (0x500, 0x300)])
    check(shim_hits == [0x500], f"a call from inside a shim is skipped: {shim_hits}")

    # cargo json
    msg = json.dumps(
        {
            "reason": "compiler-artifact",
            "package_id": "path+file:///r/crates/wz-link-lwip#wz-link-lwip@0.1.0",
            "target": {"name": "wz_link_lwip", "kind": ["lib"], "src_path": "/r/crates/wz-link-lwip/src/lib.rs"},
            "features": ["static-link-storage"],
            "filenames": ["/r/target/thumbv7m-none-eabi/release/deps/libwz_link_lwip.rlib"],
        }
    )
    host_msg = msg.replace("/thumbv7m-none-eabi", "")
    units, _, _ = cargo_units(msg + "\n" + host_msg + "\n", V7M)
    check(len(units) == 1 and units[0].package == "wz-link-lwip" and units[0].features == {"static-link-storage"}, f"units: {units}")

    # population
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "deploy/a").mkdir(parents=True)
        (root / "deploy/a/src").mkdir()
        (root / "deploy/a/Cargo.toml").write_text('[package]\nname = "a"\n[[bin]]\nname = "a"\n')
        (root / "deploy/a/src/main.rs").write_text("fn main() {}\n")
        table = {"a": Image("deploy/a/Cargo.toml", "bin", "a", "gated", (Build(V7M),))}
        check(population_problems(root, table) == [], f"population ok: {population_problems(root, table)}")
        (root / "deploy/b").mkdir()
        (root / "deploy/b/Cargo.toml").write_text('[package]\nname = "b"\n')
        check(any("deploy/b" in p for p in population_problems(root, table)), "an unclassified deploy image fails")
        (root / "deploy/a/src/main.rs").write_text("#[global_allocator]\nstatic H: X = X;\n")
        check(any("global_allocator" in p for p in population_problems(root, table)), "a gated image with an allocator fails")

    if failures:
        for f in failures:
            print(f"no-allocator-gate selftest FAIL: {f}", file=sys.stderr)
        return 1
    print("no-allocator-gate selftest OK")
    return 0


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def verdict(report: Report) -> tuple[int, str]:
    """Is the image in the state its row says?"""
    if report.problems:
        return 1, "cannot judge: " + "; ".join(report.problems)
    who = sorted({a[0] for a in report.first_party})
    if report.refused and report.status == "pending":
        return 0, "pending, as its row says: the toolchain refuses the link (" + ", ".join(who) + ")"
    if report.status == "gated":
        if report.clean:
            return 0, "clean, as gated"
        what = []
        if report.refused:
            what.append(f"the toolchain refuses the link ({report.refused})")
        if report.elf is not None and not report.elf.clean:
            what.append(
                f"the ELF names {len(report.elf.entry)} allocator entry point(s), "
                f"{len(report.elf.impl)} implementation(s), {len(report.elf.alloc_code)} alloc-crate symbol(s)"
            )
        if who:
            what.append("these crates carry `extern crate alloc`: " + ", ".join(who))
        return 1, "gated image allocates: " + "; ".join(what)
    if report.clean:
        return 1, "pending image is clean: promote its row to gated so the proof guards it"
    return 0, "pending, as its row says: " + report_summary(report)


def report_summary(report: Report) -> str:
    parts = []
    if report.elf is not None:
        parts.append(f"{len(report.elf.alloc_code)} alloc-crate symbols")
    parts.append(f"{len({a[0] for a in report.first_party})} crates of this repository carry alloc")
    return ", ".join(parts)


def census_index(reports: list[Report]) -> str:
    """The census of every image in one page: a table, then the worklist of the
    steps that repay it, source line by source line, across images."""
    out = [
        "NO-ALLOCATOR CENSUS (scripts/lib/no_allocator_link_gate.py --census)",
        "",
        "Per image and target: what the linked ELF still names of an allocator, how many crates of this",
        "repository still write `extern crate alloc` in the build, and how many branches go to an allocation",
        "entry (and to which source lines). `alloc call sites` counts branches to alloc/realloc/zeroed;",
        "frees are counted apart. now=CLEAN is the proof; ALLOCATES is the worklist below.",
        "",
        f"{'image [label]':46} {'status':8} {'now':9} {'A':>3} {'B':>3} {'C':>4} {'crates':>6} {'sites':>6} {'lines':>5} {'frees':>5}",
    ]
    for r in reports:
        e = r.elf
        sites = sum(sum(s.kinds.values()) for s in r.sites)
        out.append(
            f"{r.image + ' [' + r.label + '] ' + r.target.replace('-none-eabi', ''):46} {r.status:8} "
            f"{'CLEAN' if r.clean else 'ALLOCATES':9} "
            f"{len(e.entry) if e else '-':>3} {len(e.impl) if e else '-':>3} {len(e.alloc_code) if e else '-':>4} "
            f"{len({a[0] for a in r.first_party}):>6} {sites:>6} {len(r.sites):>5} {r.frees:>5}"
        )
    out += ["", "A = allocator entry points, B = allocator implementations, C = alloc-crate symbols.", ""]
    carriers: dict[str, set[str]] = defaultdict(set)
    lines: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in reports:
        tag = f"{r.image}[{r.label}]"
        for crate, _, _, _ in r.first_party:
            carriers[crate].add(tag)
        for s in r.sites:
            for kind in s.kinds:
                lines[(s.crate, s.where)][kind].add(tag)
    out.append("CRATES OF THIS REPOSITORY THAT WRITE `extern crate alloc`, and the images that compile them")
    for crate in sorted(carriers):
        out.append(f"  {crate}: {len(carriers[crate])} build(s): {', '.join(sorted(carriers[crate]))}")
    out += ["", "SOURCE LINES THAT ASK FOR MEMORY, by crate (images each is reached from)"]
    for crate in sorted({c for c, _ in lines}):
        out.append(f"  {crate}")
        for (c, where), kinds in sorted(lines.items()):
            if c != crate:
                continue
            images = sorted({t for ts in kinds.values() for t in ts})
            out.append(f"      {where}  ({'/'.join(sorted(kinds))})  <- {len(images)} build(s)")
    return "\n".join(out)


def run_image(name: str, args: argparse.Namespace, collect: list[Report] | None = None) -> int:
    image = IMAGES[name]
    if args.expect:
        # Judge the image against a state its row does not claim: `--expect
        # gated` on a pending image is how the report of what stands in its
        # way is shown as a failure, the red a promoted row would give.
        image = replace(image, status=args.expect)
    builds = [b for b in image.builds if not args.target or b.target == args.target]
    if not builds:
        raise SystemExit(f"no_allocator_link_gate: {name} has no build for {args.target}")
    rc = 0
    for build in builds:
        report = judge_build(name, image, build, args)
        if collect is not None:
            collect.append(report)
        text = render(report)
        code, why = verdict(report)
        print(text)
        print(f"no-allocator-gate {name} [{build.label}] {build.target}: {'OK' if code == 0 else 'FAIL'} ({why})")
        if args.report:
            with open(args.report, "a", encoding="utf-8") as fh:
                fh.write(text + "\n\n")
        rc = max(rc, code)
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--population", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--image")
    parser.add_argument("--expect", choices=("gated", "pending"))
    parser.add_argument("--target")
    parser.add_argument("--elf")
    parser.add_argument("--units")
    parser.add_argument("--lines", action="store_true")
    parser.add_argument("--report")
    parser.add_argument("--census")
    args = parser.parse_args()
    if args.selftest:
        return _selftest()
    if args.list:
        # The builds a lane runs the gate on: one `<image> <target>` row each.
        for name, image in IMAGES.items():
            for build in image.builds if image.ci else ():
                print(name, build.target)
        return 0
    if args.population:
        problems = population_problems(REPO_ROOT, IMAGES)
        for p in problems:
            print(f"no-allocator-gate FAIL: {p}", file=sys.stderr)
        if not problems:
            print(f"no-allocator-gate population OK ({len(IMAGES)} images classified)")
        return 1 if problems else 0
    if args.census:
        out = Path(args.census)
        out.mkdir(parents=True, exist_ok=True)
        args.lines = True
        collected: list[Report] = []
        for name in IMAGES:
            args.report = str(out / f"{name}.txt")
            Path(args.report).write_text("")
            try:
                run_image(name, args, collected)
            except SystemExit as exc:
                print(f"census: {name}: {exc}", file=sys.stderr)
        (out / "index.txt").write_text(census_index(collected) + "\n", encoding="utf-8")
        return 0
    if args.image:
        if args.image not in IMAGES:
            print(f"no-allocator-gate: unknown image {args.image}; known: {', '.join(IMAGES)}", file=sys.stderr)
            return 2
        return run_image(args.image, args)
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

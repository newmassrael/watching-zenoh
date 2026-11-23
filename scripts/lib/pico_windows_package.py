#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4551 (no register item) -- the Windows release packages of the pico C ABI library, one for each
width of Windows: x64 and x86.

    pico_windows_package.py --build OUT --profile ID [--arch x64|x86] [--form single|split]
                            [--stdlib nostd|std]
    pico_windows_package.py --measure [--arch x64|x86]
    pico_windows_package.py --verify DIR|ZIP
    pico_windows_package.py --test ZIP
    pico_windows_package.py --release DIR TAG
    pico_windows_package.py --selftest

`--build` makes, on a Windows host with the MSVC toolchain, a package of `wz-capi-pico` built from a
registered profile (`configs/profiles/<ID>.conf`, resolved strictly by the pinned Kconfig
interpreter, as `wz_config.py --resolve-features pico` resolves it) for each width `--arch` names,
both when it names none: the DLL in a debug and a release build, each with its import library and
its symbols, the headers a program compiles against, the examples, a configuration sample, the
usage notes and release notes, the licence of the library and the notices of everything it links,
and `manifest.json`, the size and SHA-256 of every other file. For each width it writes
`OUT/<name>/`, `OUT/<name>.zip` and `OUT/<name>.zip.sha256`, the width in `<name>` and the Rust
target in the manifest's `target`.

`--form` names the form of the library, both when it names none: `single`, the one DLL
`wz_capi_pico.dll` the default build makes, the core and the doors of the additional features in it;
or `split`, the same build as two DLLs, the core (`wz-capi-pico` compiled with
`--cfg wz_additional_apart`) and the additional library `wz_capi_pico_ext.dll` (`wz-capi-pico-ext`,
the doors' sources over the core's C ABI, importing from the core's DLL), each with its import
library and symbols, from the profile's one feature list (docs/capi-pico-additional-library.md). A
program links every library of its package; the split package's name says `split` and its manifest
`form` and `libraries`.

`--stdlib` names the standard library the DLL is built with, `nostd` when it names none: `nostd`,
the form a release ships (owner, 2026-11-23: docs/c-abi-engine-and-memory.md, E7), the MCU build
over the system's own calls in the place of `std` (`os-windows` for `engine-coop`: E4 and phase
P4), built with the `capi-nostd` profile and configuration and, for the debug build, the dev profile
with `panic = "abort"`; or `std`, the host's, which no release carries and which is built to compare
and measure against. The library without `std` is a form of the cooperative engine and of the one
library: a profile on the tokio engine, a capability that still selects `std` and the split form
are refused by name. Its name and its manifest's `stdlib` say `nostd`, and a name with no such word
is a library with `std`. Each DLL's sizes are printed as it is packaged.

`--measure` builds the size gate's client (`scripts/lib/capability_cost_gate.py`, cases
`pico-client-coop` and `pico-client-coop-nostd`: the same features, profile and configuration) for
each width `--arch` names, both when it names none, with and without `std`, and prints each DLL's
sizes, read from its own section table as `size` reads a library on Linux, and the ratio of the
two. That gate reads ELF libraries on Linux; a Windows DLL is measured only on Windows, so its
cases are printed here and gate nothing yet.

`--verify` re-hashes a package (a directory, or a zip it extracts first) against its manifest: a
file that differs, one the manifest names that is missing, and one it does not name are each a
finding. `--test` is the regression test of a zip on a Windows host: it extracts and verifies it,
then compiles `crates/wz-capi-pico/csrc/pico_layout_pins.c` (whose static assertions hold the words
the library writes into each type a program allocates to what the package's headers give it), every
example and `crates/wz-capi-pico/tests/c/package_check.c` against the package's own `include/` and
import library with MSVC's `cl` of the package's width (its manifest's `target`), for the debug and
the release build, and runs each with the package's `bin/` on the path. The check program holds the
DLL to the conformance digest of the package's `build-statement.json` and reads the configuration
sample through it.

`--release` holds the packages a release workflow is about to attach (the zips and their
`.zip.sha256` files in `DIR`) to the release cut at `TAG` from the checkout's `HEAD`, on any host:
exactly one package of every width and of every form of the standard library a release carries
(`RELEASE_STDLIBS`), and none of another, each zip matching its `.zip.sha256` and its manifest,
each built from `HEAD` with no change uncommitted and named as `--build` names it, all of one
version and profile, and `TAG` naming that version (`v<version>` or `v<version>-<suffix>`). Then
it writes `DIR/SHA256SUMS`, the `.zip.sha256` lines of every zip in name order; nothing is written
on a finding.

## Why each piece is what it is

* The headers are zenoh-pico's own, as the vendored library's build installs them, with
  `zenoh-pico/config.h` replaced by the one of THIS library's arm, rendered from the build's own
  feature list and limits (the rendering `wz_config.py --pico-config-h` does, called here on the
  exact list the DLL is built with, so no default feature can be assumed on top of it). A program
  compiled against the vendored default `config.h` would allocate the structs of another arm.
  `wz_ext.h` is beside them: the doors that are wz's own.
* The build environment is the profile's alone. A `WZ_LIMIT_*` or `WZ_POLICY_*` the caller's
  environment states would change the library and not the statement the package carries, so it is
  refused, by name, before anything is built.
* The DLL is linked with `/Brepro` (no clock reading in the image) and `/PDBALTPATH:%_PDB%` (the
  symbols are named by file name, not by the build machine's path), so the bytes depend on the
  sources, the toolchain and the paths of the build host's checkout and registry, which a hosted
  runner keeps fixed. Whether two builds give the same bytes is not measured here.
* The notices are derived, never listed: the packages are the normal-dependency graph of the build
  (`cargo tree` with the profile's features for the target, procedural macros apart), each joined
  with its manifest (`cargo metadata`) for its licence expression, source, and the licence, copyright
  and notice files it ships, which are copied. A package that names no licence at all is refused.
  The Rust standard library, which the compiler links, is noticed from the toolchain's own
  `COPYRIGHT-library.html`; the zenoh-pico headers from the vendored tree's `LICENSE` and notice.
* The zip is deterministic for one staged tree: entries in path order, every timestamp the
  commit's (`SOURCE_DATE_EPOCH` when set), one file mode, no directory entries.

Exit 0 on success, 1 on a failed verify or test, 2 on a refusal.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
# The widths a package is made for: the name the package and `--arch` give it -> (the Rust target
# its DLL is built for, the argument of `vcvarsall.bat` that sets up MSVC's compiler of the same
# width). A program of one width links the package of that width only.
ARCHES = {
    "x64": ("x86_64-pc-windows-msvc", "x64"),
    "x86": ("i686-pc-windows-msvc", "x86"),
}
CRATE = "wz-capi-pico"
LIBRARY = "wz_capi_pico"
# The second form of the library: the core alone (`CRATE` with `APART_CFG`) and the doors of the
# additional features as a library of their own (`EXT_CRATE`), which imports the core's DLL through C
# (docs/capi-pico-additional-library.md).
EXT_CRATE = "wz-capi-pico-ext"
EXT_LIBRARY = "wz_capi_pico_ext"
APART_CFG = "wz_additional_apart"
# The forms of a package: its name for `--form` -> the libraries it ships, in the order a program
# links them. A program is written the same for both and links every library of its package.
FORMS = {
    "single": (LIBRARY,),
    "split": (LIBRARY, EXT_LIBRARY),
}
# The standard library a package's DLL is built with (`--stdlib`): `std`, the host's, or `nostd`,
# the cooperative engine over the system's own calls in its place (`NOSTD_FEATURE` named where
# the profile names `engine-coop`). A release carries the library without `std` alone (owner,
# 2026-11-23); the one with it is built to compare and measure against, so `--build` makes the
# released form unless told another.
STDLIBS = ("std", "nostd")
DEFAULT_STDLIB = "nostd"
RELEASE_STDLIBS = ("nostd",)
NOSTD_FEATURE = "os-windows"
# How a library without `std` is built (crates/Cargo.toml, crates/.cargo/capi-nostd.toml): the
# release build with the `capi-nostd` profile (abort, fat LTO) and its configuration, and the debug
# build with the dev profile told to abort, since nothing without `std` unwinds.
NOSTD_PROFILE = "capi-nostd"
NOSTD_CONFIG = ".cargo/capi-nostd.toml"
NOSTD_BUILDS = (("release", ["--profile", NOSTD_PROFILE, "--config", NOSTD_CONFIG]),
                ("debug", ["--config", NOSTD_CONFIG]))
NOSTD_DEBUG_ENV = {"CARGO_PROFILE_DEV_PANIC": "abort"}
# The size gate's client on Windows (`--measure`): (case, features, cargo's profile arguments), the
# features and profile of `capability_cost_gate.py`'s `pico-client-coop` and
# `pico-client-coop-nostd`, the second's form for Windows.
SIZE_CASES = (
    ("pico-client-coop-windows", "engine-coop,link-udp", ["--release"]),
    ("pico-client-coop-nostd-windows", f"{NOSTD_FEATURE},link-udp",
     ["--profile", NOSTD_PROFILE, "--config", NOSTD_CONFIG]),
)
# A PE section's characteristics (the image format's section flags): stored nowhere in the file,
# written at run time, and dropped once the image is loaded.
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_WRITE = 0x80000000
PROFILE_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FORMAT = "wz-pico-windows-package"
# 3: `stdlib` joined the manifest (`--stdlib`); a version-2 manifest cannot say which a DLL is.
FORMAT_VERSION = 3
MANIFEST = "manifest.json"
STATEMENT = "build-statement.json"

# The two builds a package carries: (directory in the package, cargo's profile arguments).
BUILDS = (("release", ["--release"]), ("debug", []))
# Full debug information in both builds: the symbols are in the PDB beside the DLL, not in it.
DEBUG_INFO_ENV = {"CARGO_PROFILE_DEV_DEBUG": "full", "CARGO_PROFILE_RELEASE_DEBUG": "full",
                  "CARGO_PROFILE_CAPI_NOSTD_DEBUG": "full"}
# Given to the link of the DLL alone (`cargo rustc`), so no dependency is rebuilt for them.
LINK_ARGS = ["-C", "link-arg=/Brepro", "-C", "link-arg=/PDBALTPATH:%_PDB%"]
# The variables a build reads its limits and policies from; the profile states them, nobody else.
STATED_PREFIXES = ("WZ_LIMIT_", "WZ_POLICY_")

PACKAGE_DOCS = CRATES / CRATE / "package"
EXAMPLES_DIR = CRATES / CRATE / "examples" / "c"
# The program the C ABI examples job runs as the example of a transport the program supplies.
TRANSPORT_EXAMPLE = CRATES / CRATE / "tests" / "c" / "pico_app_transport.c"
CHECK_PROGRAM = CRATES / CRATE / "tests" / "c" / "package_check.c"
# The static assertions that hold the Rust layer's word counts to the program's header.
LAYOUT_PINS = CRATES / CRATE / "csrc" / "pico_layout_pins.c"
EXT_HEADER = CRATES / "wz-capi-core" / "include" / "wz_ext.h"
PICO_TREE = ROOT / "vendor" / "zenoh-pico"
# Files copied as they are: (path in the package, source).
FIXED_FILES = (
    ("LICENSE", ROOT / "LICENSE"),
    ("LICENSE-COMMERCIAL.md", ROOT / "LICENSE-COMMERCIAL.md"),
    ("README.md", PACKAGE_DOCS / "README.md"),
    ("config/message-catalog.sample.json5", CRATES / "wz-app-frame" / "catalog" / "synthetic.json5"),
    ("config/message-catalog.schema.json", ROOT / "deploy" / "message-catalog.schema.json"),
    ("config/wz-config.schema.json", ROOT / "deploy" / "wz-config.schema.json"),
    ("include/wz_ext.h", EXT_HEADER),
)
CATALOG_SAMPLE = "config/message-catalog.sample.json5"

# A file a package ships that states its licence, copyright or notices, by its name.
LICENSE_FILE_RE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$", re.IGNORECASE)
# A directory of licence texts (the REUSE layout).
LICENSE_DIRS = ("LICENSES",)
# A copy of a crates.io package carried under `third-party/` with one changed arm says how here.
PATCH_NOTE = "WZ-PATCH.md"
CRATES_IO_SOURCES = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
# Zip timestamps cannot be earlier than this.
ZIP_EPOCH_FLOOR = 315532800  # 1980-01-01T00:00:00Z


class Refusal(Exception):
    """The package will not be made as asked."""


# ---------------------------------------------------------------------------
# Pure pieces (the selftest drives them)
# ---------------------------------------------------------------------------


def stated_in_environment(environ: dict[str, str]) -> list[str]:
    """The limit and policy variables an environment states, which a package build refuses."""
    return sorted(name for name in environ if name.startswith(STATED_PREFIXES))


def parse_env_lines(lines: list[str]) -> dict[str, str]:
    """`NAME=value` lines (the --resolve-env form) as a mapping."""
    out: dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition("=")
        if not sep or not name:
            raise Refusal(f"`{line}` is not NAME=value")
        out[name] = value
    return out


def package_name(version: str, profile: str, arch: str, commit: str, form: str = "single",
                 stdlib: str = "std") -> str:
    """The package's name: the one library's carries no form, the split one's says `split`; the
    library with `std` carries no word for it, the one without says `nostd`."""
    shape = "" if form == "single" else f"-{form}"
    bare = "" if stdlib == "std" else f"-{stdlib}"
    return f"{CRATE}-{version}-{profile}-windows-{arch}{shape}{bare}-{commit[:10]}"


def form_of(manifest: dict) -> str:
    """The form a package's manifest states; a form no package is made in is refused."""
    form = manifest.get("form")
    if form not in FORMS:
        raise Refusal(f"`{form}` is the form of no package ({', '.join(FORMS)})")
    return form


def stdlib_of(manifest: dict) -> str:
    """The standard library a package's manifest states its DLL is built with; any other word, or
    none, is refused."""
    stdlib = manifest.get("stdlib")
    if stdlib not in STDLIBS:
        raise Refusal(f"`{stdlib}` is the standard library of no package ({', '.join(STDLIBS)})")
    return stdlib


def stdlib_forms(stdlib: str) -> list[str]:
    """The forms a package of standard library `stdlib` is made in: every form with `std`, and the
    one library without it, since the additional library (`EXT_CRATE`) has no form without `std`."""
    return list(FORMS) if stdlib == "std" else ["single"]


def nostd_features(features: list[str], table: dict[str, list[str]]) -> list[str]:
    """The feature list of the library without `std` for a profile's list on the cooperative
    engine: `NOSTD_FEATURE` in the place of `engine-coop`, `std` left out, the rest as it is.
    `table` is the crate's feature table, read for what each feature turns on. A list on the tokio
    engine has no such form, and a feature that still turns `std` on would build the library with
    it after all, which the crate refuses (`src/lib.rs`): both are refused here by name, before a
    build."""
    if "engine-coop" not in features:
        raise Refusal("the library without `std` is a form of the cooperative engine, and the "
                      "profile's list names no `engine-coop`")
    out = [NOSTD_FEATURE] + [f for f in features if f not in ("engine-coop", "std")]
    try:
        with_std = [f for f in out if "std" in wz_config.enabled_features(table, [f])]
    except KeyError as err:
        raise Refusal(f"the feature list names what the crate does not have: {err}") from err
    if with_std:
        raise Refusal(f"{', '.join(with_std)} turn(s) `std` on, so no library without it carries "
                      "this profile")
    return out


def ext_features(features: list[str], declared: set[str]) -> list[str]:
    """The features of the core's list the additional library declares, in the list's order: its
    doors and the arm of the C types they read, which the two libraries must agree on."""
    return [feature for feature in features if feature in declared]


def arch_of_target(target: str) -> str:
    """The width a package's manifest `target` is built for; a target no package is made for is
    refused, as a package of it cannot be compiled against with either compiler."""
    for arch, (rust_target, _) in ARCHES.items():
        if rust_target == target:
            return arch
    raise Refusal(f"`{target}` is the target of no Windows package ({', '.join(t for t, _ in ARCHES.values())})")


def cl_script(vs: pathlib.Path, vcvars: str, work: pathlib.Path, args: str) -> str:
    """A batch file that runs MSVC's `cl` with `args` in `work`, in the environment
    `vcvarsall.bat <vcvars>` sets up: the compiler, linker and libraries of that width. zenoh-pico's
    Windows build is C11 with `ZENOH_WINDOWS`, and so is every program compiled here."""
    return ("@echo off\r\n"
            f'call "{vs}\\VC\\Auxiliary\\Build\\vcvarsall.bat" {vcvars} > nul\r\n'
            f'cd /d "{work}"\r\n'
            f"cl /nologo /std:c11 /DZENOH_WINDOWS {args}\r\n")


def parse_tree(text: str) -> set[tuple[str, str]]:
    """The (name, version) of every package `cargo tree --prefix none --format {p}` prints: the
    name, then the version with its `v`, then what cargo adds (the source of a path package, a
    `(proc-macro)` mark, the `(*)` of a package printed before)."""
    out: set[tuple[str, str]] = set()
    for line in text.splitlines():
        words = line.split()
        if len(words) < 2 or not words[1].startswith("v"):
            continue
        out.add((words[0], words[1][1:]))
    return out


def source_of(pkg: dict, root: pathlib.Path) -> str:
    """Where a package came from, in words that name no machine's path."""
    source = pkg.get("source")
    if source is None:
        here = pathlib.Path(pkg["manifest_path"]).parent
        try:
            return "path " + here.resolve().relative_to(root.resolve()).as_posix()
        except ValueError as err:
            raise Refusal(f"{pkg['name']} {pkg['version']} is a path package outside the checkout") from err
    if source.startswith(CRATES_IO_SOURCES):
        return "crates.io"
    return source


def license_texts(pkg_dir: pathlib.Path, license_file: str | None) -> list[pathlib.Path]:
    """The files a package ships that state its licence, copyright or notices, and its patch note
    when it is a modified copy, as paths relative to the package's directory, in order."""
    found: set[pathlib.Path] = set()
    for entry in pkg_dir.iterdir():
        if entry.is_file() and (LICENSE_FILE_RE.match(entry.name) or entry.name == PATCH_NOTE):
            found.add(pathlib.Path(entry.name))
        elif entry.is_dir() and entry.name in LICENSE_DIRS:
            found.update(p.relative_to(pkg_dir) for p in entry.rglob("*") if p.is_file())
    if license_file:
        named = pkg_dir / license_file
        if named.is_file():
            found.add(pathlib.Path(os.path.normpath(license_file)))
    return sorted(found, key=lambda p: p.as_posix())


def notice_rows(ids: set[tuple[str, str]], metadata: dict, root: pathlib.Path) -> tuple[list[dict], list[str]]:
    """One row per third-party package of `ids` (packages of the workspace are the library itself
    and are left out), and the problems: a package the manifest list does not have or has twice,
    and one that names no licence."""
    members = set(metadata["workspace_members"])
    by_key: dict[tuple[str, str], list[dict]] = {}
    for pkg in metadata["packages"]:
        by_key.setdefault((pkg["name"], pkg["version"]), []).append(pkg)
    rows: list[dict] = []
    problems: list[str] = []
    for key in sorted(ids):
        found = by_key.get(key, [])
        if len(found) != 1:
            problems.append(f"{key[0]} {key[1]}: the dependency graph names it and the manifest list has "
                            f"{len(found)} package(s) of that name and version, not one")
            continue
        pkg = found[0]
        if pkg["id"] in members:
            continue
        expression = pkg.get("license")
        license_file = pkg.get("license_file")
        if not expression and not license_file:
            problems.append(f"{key[0]} {key[1]}: names no licence (neither `license` nor `license-file`)")
            continue
        pkg_dir = pathlib.Path(pkg["manifest_path"]).parent
        rows.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "license": expression or f"see {license_file}",
            "source": source_of(pkg, root),
            "dir": pkg_dir,
            "texts": license_texts(pkg_dir, license_file),
        })
    return rows, problems


def text_dir(row: dict) -> str:
    return f"licenses/{row['name']}-{row['version']}"


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def notice_table(rows: list[dict]) -> list[str]:
    out = ["| Package | Version | Licence | Source | Texts |", "|---|---|---|---|---|"]
    for row in rows:
        texts = ", ".join(f"`{text_dir(row)}/{t.as_posix()}`" for t in row["texts"]) or "none shipped"
        out.append(f"| {cell(row['name'])} | {cell(row['version'])} | {cell(row['license'])} | "
                   f"{cell(row['source'])} | {texts} |")
    return out


def render_notices(profile: str, target: str, linked: list[dict], compile_time: list[dict], rust: dict,
                   pico: dict, libraries: tuple[str, ...] = (LIBRARY,),
                   crates: tuple[str, ...] = (CRATE,)) -> str:
    """THIRD-PARTY-NOTICES.md: what the libraries link and the texts that cover it."""
    textless = [row for row in linked if not row["texts"]]
    one = len(libraries) == 1
    named = " and ".join(f"`release/bin/{lib}.dll` and `debug/bin/{lib}.dll`" for lib in libraries)
    graphs = " and ".join(f"`{crate}`" for crate in crates)
    out = [
        "# Third-party notices",
        "",
        f"The {'library' if one else 'libraries'} of this package ({named}) {'is' if one else 'are'}",
        "watching-zenoh, under the licence in `LICENSE` or a commercial licence (`LICENSE-COMMERCIAL.md`).",
        f"{'It links' if one else 'They link'} the packages listed below, each under its own licence.",
        "",
        "This list is derived from the build, not written by hand: it is the normal-dependency graph of",
        f"{graphs} built with the features of profile `{profile}` for `{target}` (`cargo tree`),",
        "each package joined with its manifest (`cargo metadata`) for its licence expression and its",
        "source. The texts are the licence, copyright and notice files each package ships, copied under",
        "`licenses/`; a copy of a package carried in the watching-zenoh tree with a changed arm ships its",
        f"`{PATCH_NOTE}`, which says what changed.",
        "",
        f"## Linked packages ({len(linked)})",
        "",
    ] + notice_table(linked)
    if textless:
        out += [
            "",
            f"## Linked packages that ship no licence text ({len(textless)})",
            "",
            "Each of these states its licence by expression only; the package carries no file to copy.",
            "",
        ] + [f"- {row['name']} {row['version']}: {row['license']}" for row in textless]
    out += [
        "",
        f"## Compile-time only ({len(compile_time)})",
        "",
        "Procedural macros and what they depend on. They run while the library is compiled and are",
        "not linked into it; the code they generate is.",
        "",
    ] + notice_table(compile_time) + [
        "",
        "## The Rust standard library",
        "",
        f"The compiler links its standard library into the library: `{rust['release']}`. Its copyright",
        f"notice is `{rust['dir']}/{rust['notice']}`, with the licence texts it names beside it.",
        "",
        "## The zenoh-pico headers",
        "",
        "The headers under `include/`, except `include/wz_ext.h`, are zenoh-pico's",
        f"(version {pico['version']}, commit {pico['commit']}), under Apache-2.0 OR EPL-2.0:",
        f"`{pico['dir']}/LICENSE` and `{pico['dir']}/NOTICE.md`. `include/zenoh-pico/config.h` is",
        "rendered from zenoh-pico's `config.h.in` for this library's build.",
        "",
    ]
    return "\n".join(out)


def file_rows(directory: pathlib.Path) -> list[dict]:
    """Every file of a package but its manifest, with its size and SHA-256, in path order."""
    out = []
    for path in sorted((p for p in directory.rglob("*") if p.is_file()), key=lambda p: p.relative_to(directory).as_posix()):
        rel = path.relative_to(directory).as_posix()
        if rel == MANIFEST:
            continue
        data = path.read_bytes()
        out.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return out


def render_json(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def verify_findings(directory: pathlib.Path) -> list[str]:
    """What differs between a package directory and its manifest."""
    path = directory / MANIFEST
    if not path.is_file():
        return [f"no {MANIFEST} in {directory.name}"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        listed = {row["path"]: row for row in manifest["files"]}
    except (ValueError, KeyError, TypeError) as err:
        return [f"{MANIFEST} is not a package manifest: {err}"]
    if manifest.get("format") != FORMAT or manifest.get("format_version") != FORMAT_VERSION:
        return [f"{MANIFEST} is not of format {FORMAT} {FORMAT_VERSION}"]
    present = {row["path"]: row for row in file_rows(directory)}
    out = []
    for rel in sorted(listed.keys() - present.keys()):
        out.append(f"{rel}: the manifest names it and the package does not have it")
    for rel in sorted(present.keys() - listed.keys()):
        out.append(f"{rel}: in the package and not in the manifest")
    for rel in sorted(listed.keys() & present.keys()):
        want, have = listed[rel], present[rel]
        if (want.get("size"), want.get("sha256")) != (have["size"], have["sha256"]):
            out.append(f"{rel}: size {have['size']} sha256 {have['sha256']}, the manifest says "
                       f"size {want.get('size')} sha256 {want.get('sha256')}")
    return out


def zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    t = time.gmtime(max(epoch, ZIP_EPOCH_FLOOR))
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2)


def write_zip(directory: pathlib.Path, out: pathlib.Path, epoch: int) -> None:
    """The package directory as a zip under its own name, the same bytes for the same tree."""
    stamp = zip_time(epoch)
    files = sorted((p for p in directory.rglob("*") if p.is_file()), key=lambda p: p.relative_to(directory).as_posix())
    with zipfile.ZipFile(out, "w") as archive:
        for path in files:
            info = zipfile.ZipInfo(f"{directory.name}/{path.relative_to(directory).as_posix()}", date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)


def extracts_under(root: pathlib.Path, member: str) -> bool:
    """Whether an archive member lands under `root`: the member's path, joined to the root and
    resolved, is relative to the resolved root. A `..` that climbs out, an absolute name and a
    Windows drive name each resolve elsewhere, on either host's path rules."""
    base = root.resolve()
    try:
        (base / member).resolve().relative_to(base)
    except ValueError:
        return False
    return True


def extract_zip(archive: pathlib.Path, into: pathlib.Path) -> pathlib.Path:
    """Extract a package zip and return its one top directory; a zip of anything else is refused."""
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        tops = {name.split("/", 1)[0] for name in names}
        if len(tops) != 1 or not all(extracts_under(into, name) for name in names):
            raise Refusal(f"{archive.name} is not one package directory")
        z.extractall(into)
    return into / tops.pop()


def artifact_files(report: str, target_name: str) -> list[str]:
    """The files cargo reports for the library target `target_name` (`compiler-artifact`)."""
    out: list[str] = []
    for line in report.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        target = msg.get("target") or {}
        if msg.get("reason") == "compiler-artifact" and target.get("name") == target_name and "cdylib" in target.get("kind", []):
            out = list(msg.get("filenames", []))
    return out


def pico_include(report: str) -> pathlib.Path:
    """The include directory the vendored zenoh-pico build installed, from cargo's report."""
    found = set()
    for line in report.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") == "build-script-executed" and "zenoh-pico-sys" in msg.get("package_id", ""):
            found.add(os.path.join(msg["out_dir"], "include"))
    if len(found) != 1:
        raise Refusal(f"cargo reported {len(found)} zenoh-pico-sys build(s), not one")
    return pathlib.Path(found.pop())


def pick(files: list[str], suffix: str) -> pathlib.Path | None:
    hits = [pathlib.Path(f) for f in files if f.lower().endswith(suffix)]
    return hits[0] if len(hits) == 1 else None


def release_notes(template: str, facts: dict) -> str:
    """The release notes: the written part, then what this build is, from its statement."""
    statement = facts["statement"]
    on = [c["id"] for c in statement["capabilities"] if c["supported"]]
    limits = [f"{x['id']} = {x['value']} (default {x['default']})" for x in statement["limits"] if x["value"] != x["default"]]
    policies = [f"{p['id']} = {p['value']} (upstream {p['upstream']})" for p in statement["policies"] if p["value"] != p["upstream"]]
    libraries = FORMS[facts.get("form", "single")]
    form = ("one library, `" + libraries[0] + ".dll`" if len(libraries) == 1 else
            "the core and the additional library built apart from one feature list, "
            + ", ".join(f"`{lib}.dll`" for lib in libraries) + " (a program links both)")
    out = [
        template.rstrip("\n"),
        "",
        "## This build",
        "",
        f"- Package: `{facts['name']}`",
        f"- Form: {form}",
        f"- Library version: {facts['version']}",
        f"- Source: commit `{facts['commit']}`" + ("" if facts["tree_clean"] else " with changes not committed"),
        f"- Toolchain: `{facts['rustc']}`, target `{facts['target']}`",
        f"- Profile: `{facts['profile']}` (`configs/profiles/{facts['profile']}.conf`)",
        f"- Conformance digest: `{statement['digest']}` (what `wz_ext_conformance_digest()` answers)",
        f"- Engine: {statement['engine']}",
        "- Rust standard library: " + ("linked (`std`)" if facts.get("stdlib", "std") == "std" else
                                       "not linked: `core` and `alloc` over the system's own calls "
                                       f"(`{NOSTD_FEATURE}`), the process heap as its allocator, a "
                                       "panic ends the process"),
        f"- Capabilities ({len(on)}): " + ", ".join(f"`{c}`" for c in on),
        "- Limits off their default: " + ("; ".join(limits) if limits else "none"),
        "- Policies off upstream's: " + ("; ".join(policies) if policies else "none"),
        f"- Cargo features: `{','.join(facts['features'])}`",
        "",
    ]
    return "\n".join(out)


def pe_sections(image: bytes) -> list[tuple[str, int, int]]:
    """(name, size in memory, characteristics) of every section of a PE image, read from its own
    section table; bytes that are no PE image are refused."""
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise Refusal("not a PE image: no MZ header")
    pe = int.from_bytes(image[0x3C:0x40], "little")
    if image[pe:pe + 4] != b"PE\0\0":
        raise Refusal("not a PE image: no PE signature where the MZ header points")
    coff = pe + 4
    count = int.from_bytes(image[coff + 2:coff + 4], "little")
    optional = int.from_bytes(image[coff + 16:coff + 18], "little")
    table = coff + 20 + optional
    out: list[tuple[str, int, int]] = []
    for i in range(count):
        row = image[table + 40 * i:table + 40 * (i + 1)]
        if len(row) < 40:
            raise Refusal("not a PE image: its section table runs past the file")
        name = row[:8].rstrip(b"\0").decode("ascii", "replace")
        out.append((name, int.from_bytes(row[8:12], "little"), int.from_bytes(row[36:40], "little")))
    return out


def pe_sizes(image: bytes) -> dict[str, int]:
    """A PE image's bytes in memory as `size` counts a library's on Linux, which the size gate
    reads: `text` every section loaded read-only (code, constants, the import and export tables,
    the unwind data), `data` every one written to, `bss` what is reserved and not stored. A section
    dropped once the image is loaded (`.reloc`) is none of them."""
    sizes = {"text": 0, "data": 0, "bss": 0}
    for _, size, flags in pe_sections(image):
        if flags & SCN_MEM_DISCARDABLE:
            continue
        if flags & SCN_CNT_UNINITIALIZED_DATA:
            sizes["bss"] += size
        elif flags & SCN_MEM_WRITE:
            sizes["data"] += size
        else:
            sizes["text"] += size
    return sizes


def size_line(image: bytes) -> str:
    """The sizes of a PE image as one line: the three totals, then every section."""
    sizes = pe_sizes(image)
    sections = " ".join(f"{name}={size}" for name, size, _ in pe_sections(image))
    return f"text={sizes['text']} data={sizes['data']} bss={sizes['bss']} ({sections})"


# ---------------------------------------------------------------------------
# The build (a Windows host with the MSVC toolchain)
# ---------------------------------------------------------------------------


def run(cmd: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> str:
    print("+ " + " ".join(cmd), flush=True)
    # The tools read here (cargo, git) write UTF-8; without `encoding` Python decodes a pipe with the
    # host's code page (cp1252 on a hosted Windows runner) and a single byte of another script ends
    # the build (2026-11-21: `cargo metadata`, byte 0x81).
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, encoding="utf-8")
    if proc.returncode != 0:
        raise Refusal(f"`{' '.join(cmd[:3])}` failed with exit status {proc.returncode}")
    return proc.stdout


def resolve_profile(decl: dict, profile: str) -> dict:
    if not PROFILE_ID_RE.match(profile):
        raise Refusal(f"`{profile}` is not the name of a registered profile")
    path = wz_config.PROFILES / f"{profile}.conf"
    if not path.is_file():
        known = sorted(p.stem for p in wz_config.PROFILES.glob("*.conf"))
        raise Refusal(f"no registered profile `{profile}` (known: {', '.join(known)})")
    base = wz_config.preset_header(path.read_text(encoding="utf-8")).get("base")
    if wz_config.BASE_ABI.get(base) != "pico":
        raise Refusal(f"profile {profile} is built through the {wz_config.BASE_ABI.get(base)} ABI; "
                      "this package is the pico ABI's")
    try:
        kconf = wz_config.resolve([path])
        env_lines = wz_config.resolved_limit_env(decl, kconf) + wz_config.resolved_policy_env(decl, kconf)
        # The profile's capabilities on the engine it chose, as `--resolve-features pico` prints them.
        features = wz_config.resolved_features(decl, "pico", kconf)
    except wz_config.PresetError as err:
        raise Refusal(f"profile {profile} does not resolve: {err}") from err
    statement = wz_config.resolved_statement(decl, "pico", kconf, {"kind": "presets", "inputs": [path.name]})
    return {"features": features, "env": parse_env_lines(env_lines), "statement": statement}


def arm_header(decl: dict, features: list[str], env: dict[str, str]) -> str:
    """zenoh-pico's config.h of the build of exactly `features`, with the limits `env` states."""
    try:
        table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
        enabled = wz_config.enabled_features(table, features)
        header = wz_config.pico_config_header(decl, enabled, env)
    except (KeyError, ValueError, OSError) as err:
        raise Refusal(f"the header of the library's arm did not render: {err}") from err
    conflicts = wz_config.pico_header_conflicts(decl, "pico", header)
    if conflicts:
        raise Refusal("the rendered header does not read back as the build: " + "; ".join(conflicts))
    return header


def build_selection(options: list[str]) -> tuple[list[str], list[str], str]:
    """The widths, forms and standard library `--build`'s options name (`--arch A`, `--form F`,
    `--stdlib S`, each at most once): every width, every form of the standard library and
    `DEFAULT_STDLIB` for an option not given. The library without `std` is made in the one form,
    which is then every form for an option not given. A word that is no option, an option given twice
    or without its value, a value no package is made for and the split form without `std` are
    refused."""
    chosen: dict[str, str] = {}
    rest = list(options)
    while rest:
        option = rest.pop(0)
        if option not in ("--arch", "--form", "--stdlib") or option in chosen or not rest:
            raise Refusal(f"`{option}` is not an option of --build here (--arch A, --form F, --stdlib S, "
                          "each once)")
        chosen[option] = rest.pop(0)
    stdlib = chosen.get("--stdlib", DEFAULT_STDLIB)
    if stdlib not in STDLIBS:
        raise Refusal(f"`{stdlib}` is not a standard library a package is built with ({', '.join(STDLIBS)})")
    arches = [chosen["--arch"]] if "--arch" in chosen else list(ARCHES)
    every_form = stdlib_forms(stdlib)
    forms = [chosen["--form"]] if "--form" in chosen else every_form
    for arch in arches:
        if arch not in ARCHES:
            raise Refusal(f"`{arch}` is not a width a package is made for ({', '.join(ARCHES)})")
    for form in forms:
        if form not in FORMS:
            raise Refusal(f"`{form}` is not a form a package is made in ({', '.join(FORMS)})")
        if form not in every_form:
            raise Refusal(f"the {form} form is built with `std`: its additional library ({EXT_CRATE}) "
                          "has no form without it")
    return arches, forms, stdlib


def measure_selection(options: list[str]) -> list[str]:
    """The widths `--measure`'s options name (`--arch A`, at most once): every width when it is
    not given. Anything else is refused, as `build_selection` refuses it."""
    if not options:
        return list(ARCHES)
    if len(options) != 2 or options[0] != "--arch":
        raise Refusal(f"`{' '.join(options)}` is not an option of --measure (--arch A, once)")
    if options[1] not in ARCHES:
        raise Refusal(f"`{options[1]}` is not a width a package is made for ({', '.join(ARCHES)})")
    return [options[1]]


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, stdout=subprocess.PIPE,
                          encoding="utf-8").stdout.strip()


def copy(src: pathlib.Path, dst: pathlib.Path) -> None:
    if not src.is_file():
        raise Refusal(f"{src.relative_to(ROOT).as_posix() if src.is_relative_to(ROOT) else src.name} is missing")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def rust_notice(stage: pathlib.Path, release: str) -> dict:
    sysroot = pathlib.Path(run(["rustc", "--print", "sysroot"], CRATES).strip())
    docs = sysroot / "share" / "doc" / "rust"
    notice = next((n for n in ("COPYRIGHT-library.html", "COPYRIGHT") if (docs / n).is_file()), None)
    if notice is None:
        raise Refusal("the toolchain ships no copyright notice of its standard library "
                      "(share/doc/rust/COPYRIGHT-library.html)")
    version = release.split()[1] if len(release.split()) > 1 else "unknown"
    rel = f"licenses/rust-std-{version}"
    copy(docs / notice, stage / rel / notice)
    for text in sorted((docs / "licenses").glob("*")) if (docs / "licenses").is_dir() else []:
        if text.is_file():
            copy(text, stage / rel / "licenses" / text.name)
    for text in ("LICENSE-APACHE", "LICENSE-MIT"):
        if (docs / text).is_file():
            copy(docs / text, stage / rel / text)
    return {"release": release, "dir": rel, "notice": notice}


def pico_notice(stage: pathlib.Path) -> dict:
    rel = "licenses/zenoh-pico"
    copy(PICO_TREE / "LICENSE", stage / rel / "LICENSE")
    copy(PICO_TREE / "NOTICE.md", stage / rel / "NOTICE.md")
    version = (PICO_TREE / "version.txt").read_text(encoding="utf-8").strip()
    return {"version": version, "commit": git("rev-parse", "HEAD:vendor/zenoh-pico")[:10], "dir": rel}


def copy_texts(stage: pathlib.Path, rows: list[dict]) -> None:
    for row in rows:
        for text in row["texts"]:
            copy(row["dir"] / text, stage / text_dir(row) / text)


def copy_library(report: str, library: str, where: str, stage: pathlib.Path) -> pathlib.Path:
    """Copy the DLL of `library` cargo's `report` names, its symbols and its import library into
    the `where` build of the package, and say where the DLL was."""
    files = artifact_files(report, library)
    dll = pick(files, ".dll")
    if dll is None:
        raise Refusal(f"cargo reported no single DLL of {library} for the {where} build: {files}")
    # The linker writes the import library and the symbols beside the DLL, by its name, whether
    # or not cargo lists them; `copy` refuses one that is not there.
    implib = pick(files, ".dll.lib") or dll.parent / f"{dll.name}.lib"
    pdb = pick(files, ".pdb") or dll.with_suffix(".pdb")
    copy(dll, stage / where / "bin" / f"{library}.dll")
    copy(pdb, stage / where / "bin" / f"{library}.pdb")
    copy(implib, stage / where / "lib" / f"{library}.lib")
    return dll


def build(out: pathlib.Path, profile: str, arch: str, form: str, stdlib: str = DEFAULT_STDLIB) -> pathlib.Path:
    if sys.platform != "win32":
        raise Refusal("the package is built on a Windows host: its DLL, import library and symbols are "
                      "the MSVC toolchain's")
    if arch not in ARCHES:
        raise Refusal(f"`{arch}` is not a width a package is made for ({', '.join(ARCHES)})")
    if form not in FORMS:
        raise Refusal(f"`{form}` is not a form a package is made in ({', '.join(FORMS)})")
    if stdlib not in STDLIBS:
        raise Refusal(f"`{stdlib}` is not a standard library a package is built with ({', '.join(STDLIBS)})")
    if form not in stdlib_forms(stdlib):
        raise Refusal(f"the {form} form is built with `std`: its additional library ({EXT_CRATE}) has no "
                      "form without it")
    target = ARCHES[arch][0]
    stated = stated_in_environment(dict(os.environ))
    if stated:
        raise Refusal(f"the environment states {', '.join(stated)}; the package's build is its profile's "
                      "alone, so unset them")
    decl = wz_config.load_decl()
    plan = resolve_profile(decl, profile)
    features = plan["features"]
    if stdlib == "nostd":
        features = nostd_features(features, wz_config.manifest_features(wz_config.MANIFESTS["pico"]))
    header = arm_header(decl, features, plan["env"])
    env = {**os.environ, **plan["env"], **DEBUG_INFO_ENV}

    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--all-features",
                               "--filter-platform", target], CRATES))
    crate = next((p for p in metadata["packages"] if p["name"] == CRATE and p["id"] in metadata["workspace_members"]),
                 None)
    if crate is None:
        raise Refusal(f"{CRATE} is no package of the crates workspace")
    ext = next((p for p in metadata["packages"]
                if p["name"] == EXT_CRATE and p["id"] in metadata["workspace_members"]), None)
    if form == "split" and ext is None:
        raise Refusal(f"{EXT_CRATE} is no package of the crates workspace, and the split form is built with it")
    commit = git("rev-parse", "HEAD")
    name = package_name(crate["version"], profile, arch, commit, form, stdlib)
    stage = out / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    # The headers are the same text for either width (a width is the compiler's, and the config.h
    # of the build's switches is rendered below), so they come from the vendored library's build
    # for the host, which is the build of them a host already has.
    include = pico_include(run(["cargo", "build", "-p", "zenoh-pico-sys", "--message-format=json-render-diagnostics"],
                               CRATES, env))
    for src in sorted(p for p in include.rglob("*") if p.is_file()):
        copy(src, stage / "include" / src.relative_to(include))
    (stage / "include" / "zenoh-pico" / "config.h").write_text(header, encoding="utf-8", newline="\n")

    feature_args = ["--no-default-features", "--features", ",".join(features)]
    # The additional library's own list: the profile's features it declares, over none of its
    # defaults, so the two libraries are built from the one list of the profile.
    ext_list = ext_features(features, set(ext["features"]) - {"default"}) if ext is not None else []
    ext_args = ["--no-default-features"] + (["--features", ",".join(ext_list)] if ext_list else [])
    # The split form's core is the same crate built with another cfg, so it is built in a target
    # directory of its own and the one library's build is not overwritten by it.
    split_dir = pathlib.Path(metadata["target_directory"]) / "pico-split"
    # The library without `std` is built with other profiles over every crate it links (abort, and
    # in the debug build a dev profile told so), so it has a target directory of its own too, and
    # the builds of the other form keep theirs.
    nostd_dir = pathlib.Path(metadata["target_directory"]) / "pico-nostd"

    def packaged(report: str, library: str, where: str) -> None:
        """The library into the package, and the sizes of the release build's DLL printed."""
        dll = copy_library(report, library, where, stage)
        if where == "release":
            say(f"pico-package-size on Windows {arch}: {name}: {library}.dll {size_line(dll.read_bytes())}")

    for where, cargo_profile in (BUILDS if stdlib == "std" else NOSTD_BUILDS):
        if stdlib == "nostd":
            build_env = {**env, **NOSTD_DEBUG_ENV} if where == "debug" else env
            report = run(["cargo", "rustc", "-p", CRATE, "--lib", "--target", target, *feature_args,
                          *cargo_profile, "--target-dir", str(nostd_dir),
                          "--message-format=json-render-diagnostics", "--", *LINK_ARGS], CRATES, build_env)
            packaged(report, LIBRARY, where)
            continue
        if form == "single":
            report = run(["cargo", "rustc", "-p", CRATE, "--lib", "--target", target, *feature_args,
                          *cargo_profile, "--message-format=json-render-diagnostics", "--", *LINK_ARGS],
                         CRATES, env)
            packaged(report, LIBRARY, where)
            continue
        report = run(["cargo", "rustc", "-p", CRATE, "--lib", "--target", target, *feature_args, *cargo_profile,
                      "--target-dir", str(split_dir), "--message-format=json-render-diagnostics", "--",
                      *LINK_ARGS, "--cfg", APART_CFG], CRATES, env)
        packaged(report, LIBRARY, where)
        # The additional library's imports name the core's DLL themselves (`raw-dylib`), so its link
        # needs no import library of the core.
        report = run(["cargo", "rustc", "-p", EXT_CRATE, "--lib", "--target", target, *ext_args, *cargo_profile,
                      "--target-dir", str(split_dir), "--message-format=json-render-diagnostics", "--",
                      *LINK_ARGS], CRATES, env)
        packaged(report, EXT_LIBRARY, where)

    for rel, src in FIXED_FILES:
        copy(src, stage / rel)
    for src in sorted(p for p in EXAMPLES_DIR.iterdir() if p.is_file()):
        copy(src, stage / "examples" / src.name)
    copy(TRANSPORT_EXAMPLE, stage / "examples" / TRANSPORT_EXAMPLE.name)
    (stage / STATEMENT).write_text(render_json(plan["statement"]), encoding="utf-8", newline="\n")

    # Every library of the form links its own graph; the notices cover what any of them links.
    graphs = [(CRATE, feature_args)] + ([(EXT_CRATE, ext_args)] if form == "split" else [])
    linked_ids: set[tuple[str, str]] = set()
    all_ids: set[tuple[str, str]] = set()
    for crate_name, args in graphs:
        tree_args = ["cargo", "tree", "-p", crate_name, *args, "--target", target, "--prefix", "none",
                     "--format", "{p}"]
        linked_ids |= parse_tree(run(tree_args + ["-e", "normal,no-proc-macro"], CRATES, env))
        all_ids |= parse_tree(run(tree_args + ["-e", "normal"], CRATES, env))
    linked, problems = notice_rows(linked_ids, metadata, ROOT)
    compile_time, more = notice_rows(all_ids - linked_ids, metadata, ROOT)
    problems += more
    if problems:
        raise Refusal("the notices cannot be made: " + "; ".join(problems))
    copy_texts(stage, linked + compile_time)
    rustc = run(["rustc", "-vV"], CRATES)
    release = next((line for line in rustc.splitlines() if line.startswith("release:")), "release: unknown")
    rust = rust_notice(stage, "rustc " + release.split(":", 1)[1].strip())
    pico = pico_notice(stage)
    (stage / "THIRD-PARTY-NOTICES.md").write_text(
        render_notices(profile, target, linked, compile_time, rust, pico, FORMS[form],
                       tuple(crate_name for crate_name, _ in graphs)),
        encoding="utf-8", newline="\n")

    tree_clean = git("status", "--porcelain", "--untracked-files=no") == ""
    facts = {"name": name, "version": crate["version"], "commit": commit, "tree_clean": tree_clean,
             "rustc": rust["release"], "target": target, "profile": profile, "features": features,
             "statement": plan["statement"], "form": form, "stdlib": stdlib}
    template = (PACKAGE_DOCS / "RELEASE-NOTES.md").read_text(encoding="utf-8")
    (stage / "RELEASE-NOTES.md").write_text(release_notes(template, facts), encoding="utf-8", newline="\n")

    manifest = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "name": name,
        "version": crate["version"],
        "profile": profile,
        "target": target,
        "form": form,
        "stdlib": stdlib,
        "libraries": list(FORMS[form]),
        "built_from": {"commit": commit, "tree_clean": tree_clean},
        "toolchain": {"rustc": rust["release"]},
        "statement_digest": plan["statement"]["digest"],
        "features": features,
        "files": file_rows(stage),
    }
    (stage / MANIFEST).write_text(render_json(manifest), encoding="utf-8", newline="\n")

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or git("show", "-s", "--format=%ct", "HEAD"))
    archive = out / f"{name}.zip"
    write_zip(stage, archive, epoch)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / f"{name}.zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    print(f"pico-package: {archive.name} sha256 {digest}, {len(manifest['files'])} files")
    return archive


def measure(arch: str) -> list[tuple[str, dict[str, int]]]:
    """Build the size gate's client for `arch` in each form (`SIZE_CASES`) and print each DLL's
    sizes and the ratio of the form without `std` to the one with it; the sizes, by case."""
    if sys.platform != "win32":
        raise Refusal("the client is measured on a Windows host: its DLL is the MSVC toolchain's")
    stated = stated_in_environment(dict(os.environ))
    if stated:
        raise Refusal(f"the environment states {', '.join(stated)}; the size gate's cases are built with "
                      "the build's defaults, so unset them")
    target = ARCHES[arch][0]
    rows: list[tuple[str, dict[str, int]]] = []
    for case, features, cargo_profile in SIZE_CASES:
        report = run(["cargo", "rustc", "-p", CRATE, "--lib", "--target", target, "--no-default-features",
                      "--features", features, *cargo_profile, "--message-format=json-render-diagnostics"],
                     CRATES)
        dll = pick(artifact_files(report, LIBRARY), ".dll")
        if dll is None:
            raise Refusal(f"cargo reported no single DLL of {LIBRARY} for {case}")
        image = dll.read_bytes()
        rows.append((case, pe_sizes(image)))
        say(f"pico-size on Windows {arch}: {case} ({features}): {size_line(image)}")
    (std_case, std_sizes), (nostd_case, nostd_sizes) = rows
    if std_sizes["text"]:
        say(f"pico-size on Windows {arch}: {nostd_case} text is {nostd_sizes['text'] / std_sizes['text']:.4f} "
            f"of {std_case}'s ({nostd_sizes['text'] - std_sizes['text']:+d} bytes)")
    return rows


# ---------------------------------------------------------------------------
# The regression test (a Windows host with the MSVC toolchain)
# ---------------------------------------------------------------------------


def say(line: str) -> None:
    print(line, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def vs_root() -> pathlib.Path:
    vswhere = pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        raise Refusal("no vswhere.exe: the MSVC toolchain is not installed")
    found = subprocess.run([str(vswhere), "-utf8", "-latest", "-products", "*", "-property",
                            "installationPath"], check=True, stdout=subprocess.PIPE,
                           encoding="utf-8").stdout.strip()
    if not found:
        raise Refusal("vswhere names no Visual Studio installation")
    return pathlib.Path(found)


def run_cl(vs: pathlib.Path, vcvars: str, work: pathlib.Path, name: str, args: str) -> bool:
    """Whether `cl` with `args`, in the environment of `vcvars`, succeeded (`cl_script`)."""
    bat = work / f"cl-{name}.bat"
    bat.write_text(cl_script(vs, vcvars, work, args), encoding="ascii")
    return subprocess.run(["cmd.exe", "/c", str(bat)]).returncode == 0


def compile_program(vs: pathlib.Path, vcvars: str, package: pathlib.Path, where: str, src: pathlib.Path,
                    work: pathlib.Path, libraries: tuple[str, ...]) -> pathlib.Path | None:
    """The program compiled against the package's headers and linked against the import library of
    every library of its form, as a program of that package is."""
    exe = work / f"{where}-{src.stem}.exe"
    imports = " ".join(f'"{package / where / "lib" / (library + ".lib")}"' for library in libraries)
    built = run_cl(vs, vcvars, work, f"{where}-{src.stem}",
                   f'/I"{package / "include"}" "{src}" {imports} /Fe:"{exe}"')
    return exe if built and exe.is_file() else None


def layout_pins_hold(vs: pathlib.Path, vcvars: str, package: pathlib.Path, work: pathlib.Path) -> bool:
    """Whether the layout pins compile against the package's headers with the compiler of its
    width: each is a static assertion that a type a program allocates holds the words the library
    writes into it, so a compile is the verdict and there is nothing to link or run."""
    return run_cl(vs, vcvars, work, "layout-pins",
                  f'/I"{package / "include"}" /c "{LAYOUT_PINS}" /Fo:"{work / "pico_layout_pins.obj"}"')


def test(archive: pathlib.Path) -> int:
    if sys.platform != "win32":
        raise Refusal("the package is tested on a Windows host: its programs are compiled with MSVC's cl")
    vs = vs_root()
    with tempfile.TemporaryDirectory() as tmp:
        package = extract_zip(archive, pathlib.Path(tmp) / "package")
        findings = verify_findings(package)
        for finding in findings:
            say(f"pico-package-test: {finding}")
        if findings:
            say(f"pico-package-test on Windows: {archive.name} does not match its manifest: FAIL")
            return 1
        manifest = json.loads((package / MANIFEST).read_text(encoding="utf-8"))
        arch = arch_of_target(manifest.get("target", ""))
        vcvars = ARCHES[arch][1]
        libraries = FORMS[form_of(manifest)]
        statement = json.loads((package / STATEMENT).read_text(encoding="utf-8"))
        programs = sorted(p for p in (package / "examples").glob("*.c"))
        if not programs:
            raise Refusal("the package carries no example")
        failed = 0
        pins_work = pathlib.Path(tmp) / "work-layout"
        pins_work.mkdir()
        verdict = "PASS" if layout_pins_hold(vs, vcvars, package, pins_work) else "did not compile: FAIL"
        failed += not verdict.startswith("PASS")
        say(f"pico-package-test on Windows {arch}: {LAYOUT_PINS.name}: {verdict}")
        for where, _ in BUILDS:
            work = pathlib.Path(tmp) / f"work-{where}"
            work.mkdir()
            env = {**os.environ, "PATH": str(package / where / "bin") + os.pathsep + os.environ.get("PATH", "")}
            runs = [(src, []) for src in programs]
            runs.append((CHECK_PROGRAM, [statement["digest"], str(package / CATALOG_SAMPLE)]))
            for src, args in runs:
                exe = compile_program(vs, vcvars, package, where, src, work, libraries)
                if exe is None:
                    verdict = "did not compile or link: FAIL"
                else:
                    try:
                        proc = subprocess.run([str(exe), *args], env=env, timeout=600)
                        verdict = "PASS" if proc.returncode == 0 else f"exit {proc.returncode}: FAIL"
                    except subprocess.TimeoutExpired:
                        verdict = "no answer within 600 s: FAIL"
                failed += not verdict.startswith("PASS")
                say(f"pico-package-test on Windows {arch}: {where} {src.name}: {verdict}")
        return 1 if failed else 0


# ---------------------------------------------------------------------------
# The release set (any host)
# ---------------------------------------------------------------------------

# A release tag names the packages' version, with an optional suffix (`v0.1.0`, `v0.1.0-rc1`).
RELEASE_TAG_SUFFIX = r"(-[0-9A-Za-z][0-9A-Za-z.-]*)?"
SUMS = "SHA256SUMS"


def sha256_line(archive: pathlib.Path) -> str:
    """The `.zip.sha256` line of a zip, as `--build` writes it (`sha256sum`'s format)."""
    return f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"


def release_findings(directory: pathlib.Path, commit: str, tag: str) -> tuple[list[str], str]:
    """What keeps the packages in `directory` off the release cut at `tag` from `commit`, and the
    text of the SHA256SUMS that names them (meant to be written only when there is no finding)."""
    findings: list[str] = []
    sums: list[str] = []
    seen: dict[tuple[str, str, str], str] = {}
    versions: set[str] = set()
    profiles: set[str] = set()
    archives = sorted(directory.glob("*.zip"))
    for side in sorted(directory.glob("*.zip.sha256")):
        if not side.with_name(side.name[: -len(".sha256")]).is_file():
            findings.append(f"{side.name}: no zip of that name beside it")
    for archive in archives:
        line = sha256_line(archive)
        sums.append(line)
        side = archive.with_name(archive.name + ".sha256")
        if not side.is_file():
            findings.append(f"{archive.name}: no {side.name} beside it")
        elif side.read_bytes() != line.encode("utf-8"):
            findings.append(f"{side.name} does not state the sha256 of {archive.name}")
        with tempfile.TemporaryDirectory() as tmp:
            try:
                package = extract_zip(archive, pathlib.Path(tmp))
            except (Refusal, zipfile.BadZipFile) as err:
                findings.append(f"{archive.name}: {err}")
                continue
            verified = verify_findings(package)
            findings += [f"{archive.name}: {finding}" for finding in verified]
            if verified:
                continue
            manifest = json.loads((package / MANIFEST).read_text(encoding="utf-8"))
        try:
            arch = arch_of_target(str(manifest.get("target", "")))
            form = form_of(manifest)
            stdlib = stdlib_of(manifest)
        except Refusal as err:
            findings.append(f"{archive.name}: {err}")
            continue
        if stdlib not in RELEASE_STDLIBS:
            findings.append(f"{archive.name}: built {stdlib}, a form no release carries "
                            f"({', '.join(RELEASE_STDLIBS)})")
            continue
        version = str(manifest.get("version", ""))
        profile = str(manifest.get("profile", ""))
        built = manifest.get("built_from")
        if not isinstance(built, dict):
            built = {}
        if built.get("commit") != commit:
            findings.append(f"{archive.name}: built from commit {built.get('commit')}, the release is of {commit}")
        if built.get("tree_clean") is not True:
            findings.append(f"{archive.name}: built from a tree with changes not committed")
        name = package_name(version, profile, arch, commit, form, stdlib)
        if archive.name != f"{name}.zip" or manifest.get("name") != name:
            findings.append(f"{archive.name}: its manifest makes it {name}.zip")
        if (arch, form, stdlib) in seen:
            findings.append(f"{archive.name}: a second package of {arch} {form} {stdlib}, "
                            f"beside {seen[(arch, form, stdlib)]}")
        seen.setdefault((arch, form, stdlib), archive.name)
        versions.add(version)
        profiles.add(profile)
    missing = [f"{arch} {form} {stdlib}" for stdlib in RELEASE_STDLIBS for arch in ARCHES
               for form in stdlib_forms(stdlib) if (arch, form, stdlib) not in seen]
    if missing:
        findings.append(f"no package of {', '.join(missing)}")
    if len(versions) > 1:
        findings.append(f"the packages are of versions {', '.join(sorted(versions))}, not one")
    if len(profiles) > 1:
        findings.append(f"the packages are of profiles {', '.join(sorted(profiles))}, not one")
    for version in sorted(versions):
        if not re.fullmatch(rf"v{re.escape(version)}{RELEASE_TAG_SUFFIX}", tag):
            findings.append(f"the tag `{tag}` does not name version {version} (v{version} or v{version}-<suffix>)")
    return findings, "".join(sums)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    expect("a limit and a policy in the environment are named, nothing else is",
           stated_in_environment({"WZ_LIMIT_A": "1", "WZ_POLICY_B": "on", "WZ_ARTIFACT_ROOT": "/x", "PATH": "p"})
           == ["WZ_LIMIT_A", "WZ_POLICY_B"])
    expect("an empty environment states nothing", stated_in_environment({}) == [])
    expect("env lines read as a mapping", parse_env_lines(["WZ_LIMIT_A=3", "WZ_POLICY_B=x=y"])
           == {"WZ_LIMIT_A": "3", "WZ_POLICY_B": "x=y"})
    try:
        parse_env_lines(["no-equals"])
        expect("a line with no `=` is refused", False)
    except Refusal:
        pass
    expect("the name carries version, profile, host, width and ten digits of the commit",
           package_name("0.1.0", "host-peer-ext", "x64", "0123456789abcdef")
           == "wz-capi-pico-0.1.0-host-peer-ext-windows-x64-0123456789")
    expect("the two widths make two names",
           package_name("0.1.0", "host-peer-ext", "x86", "0123456789abcdef")
           == "wz-capi-pico-0.1.0-host-peer-ext-windows-x86-0123456789")
    expect("each width is built for its own target and compiled against with its own compiler",
           ARCHES == {"x64": ("x86_64-pc-windows-msvc", "x64"), "x86": ("i686-pc-windows-msvc", "x86")})
    expect("a manifest's target names its width",
           arch_of_target("x86_64-pc-windows-msvc") == "x64" and arch_of_target("i686-pc-windows-msvc") == "x86")
    try:
        arch_of_target("aarch64-pc-windows-msvc")
        expect("a target no package is made for is refused", False)
    except Refusal:
        pass
    script = cl_script(pathlib.Path("C:/VS"), "x86", pathlib.Path("C:/w"), "/c a.c")
    expect("the compiler of the x86 width is set up by vcvarsall with its argument",
           '\\VC\\Auxiliary\\Build\\vcvarsall.bat" x86 > nul\r\n' in script
           and script.endswith("cl /nologo /std:c11 /DZENOH_WINDOWS /c a.c\r\n"))
    expect("a profile name is a word list, not a path",
           PROFILE_ID_RE.match("host-peer-ext") is not None and PROFILE_ID_RE.match("../x") is None
           and PROFILE_ID_RE.match("a--b") is None)

    tree = "\n".join([
        "wz-capi-pico v0.1.0 (C:\\w\\crates\\wz-capi-pico)",
        "tokio v1.48.0 (C:\\w\\third-party\\tokio)",
        "cfg-if v1.0.0",
        "tokio-macros v2.5.0 (proc-macro)",
        "cfg-if v1.0.0 (*)",
        "",
        "[build-dependencies]",
    ])
    expect("the tree's packages are read with their versions, once each",
           parse_tree(tree) == {("wz-capi-pico", "0.1.0"), ("tokio", "1.48.0"), ("cfg-if", "1.0.0"),
                                ("tokio-macros", "2.5.0")})

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "checkout"
        reg = pathlib.Path(tmp) / "registry"

        def pkg(name: str, version: str, where: pathlib.Path, files: dict[str, str], **fields) -> dict:
            where.mkdir(parents=True)
            (where / "Cargo.toml").write_text("", encoding="utf-8")
            for rel, body in files.items():
                (where / rel).parent.mkdir(parents=True, exist_ok=True)
                (where / rel).write_text(body, encoding="utf-8")
            return {"name": name, "version": version, "id": f"{name}@{version}",
                    "manifest_path": str(where / "Cargo.toml"), "source": fields.get("source"),
                    "license": fields.get("license"), "license_file": fields.get("license_file")}

        crates_io = CRATES_IO_SOURCES[0]
        packages = [
            pkg("ours", "0.1.0", root / "crates" / "ours", {"LICENSE": "x"}, license="LicenseRef-x"),
            pkg("dual", "1.2.3", reg / "dual-1.2.3", {"LICENSE-MIT": "m", "LICENSE-APACHE": "a", "README.md": "r",
                                                      "src/LICENSE": "nested"},
                source=crates_io, license="MIT OR Apache-2.0"),
            pkg("patched", "4.5.6", root / "third-party" / "patched", {"LICENSE": "l", PATCH_NOTE: "p"},
                license="MIT"),
            pkg("reuse", "0.0.1", reg / "reuse-0.0.1", {"LICENSES/MIT.txt": "m", "COPYRIGHT": "c"},
                source=crates_io, license="MIT"),
            pkg("filed", "2.0.0", reg / "filed-2.0.0", {"docs/TERMS.txt": "t"}, source=crates_io,
                license_file="docs/TERMS.txt"),
            pkg("bare", "3.0.0", reg / "bare-3.0.0", {}, source=crates_io, license="MIT"),
            pkg("nameless", "1.0.0", reg / "nameless-1.0.0", {"LICENSE": "?"}, source=crates_io),
            pkg("twice", "1.0.0", reg / "twice-a", {}, source=crates_io, license="MIT"),
            pkg("twice", "1.0.0", reg / "twice-b", {}, source="git+https://example.invalid/twice", license="MIT"),
        ]
        metadata = {"workspace_members": ["ours@0.1.0"], "packages": packages}
        good = {("ours", "0.1.0"), ("dual", "1.2.3"), ("patched", "4.5.6"), ("reuse", "0.0.1"),
                ("filed", "2.0.0"), ("bare", "3.0.0")}
        rows, problems = notice_rows(good, metadata, root)
        by = {row["name"]: row for row in rows}
        expect("a workspace package is the library itself and has no row", "ours" not in by)
        expect("the rows are every other package, in name order", [r["name"] for r in rows]
               == ["bare", "dual", "filed", "patched", "reuse"])
        expect("nothing is wrong with packages that each name a licence", problems == [])
        expect("a package's top-level licence files are its texts, a README and a nested file are not",
               [t.as_posix() for t in by["dual"]["texts"]] == ["LICENSE-APACHE", "LICENSE-MIT"])
        expect("a modified copy ships its patch note with its licence",
               [t.as_posix() for t in by["patched"]["texts"]] == ["LICENSE", PATCH_NOTE])
        expect("a patched copy in the checkout is named by its path in the checkout",
               by["patched"]["source"] == "path third-party/patched")
        expect("a registry package is from crates.io", by["dual"]["source"] == "crates.io")
        expect("a LICENSES directory is read whole",
               [t.as_posix() for t in by["reuse"]["texts"]] == ["COPYRIGHT", "LICENSES/MIT.txt"])
        expect("a license-file is a text, and the licence cell points at it",
               [t.as_posix() for t in by["filed"]["texts"]] == ["docs/TERMS.txt"]
               and by["filed"]["license"] == "see docs/TERMS.txt")
        expect("a package that ships no text has an empty list, not a refusal", by["bare"]["texts"] == [])
        _, problems = notice_rows({("nameless", "1.0.0")}, metadata, root)
        expect("a package that names no licence is refused by name",
               len(problems) == 1 and problems[0].startswith("nameless 1.0.0: names no licence"))
        _, problems = notice_rows({("twice", "1.0.0")}, metadata, root)
        expect("a name and version the manifest list has twice is refused", len(problems) == 1 and "2 package(s)" in problems[0])
        _, problems = notice_rows({("ghost", "9.9.9")}, metadata, root)
        expect("a package the graph names and the list lacks is refused", len(problems) == 1 and "0 package(s)" in problems[0])
        outside = pkg("outside", "1.0.0", pathlib.Path(tmp) / "elsewhere", {"LICENSE": "x"}, license="MIT")
        try:
            source_of(outside, root)
            expect("a path package outside the checkout is refused", False)
        except Refusal:
            pass

        notices = render_notices("p", "i686-pc-windows-msvc", rows, [],
                                 {"release": "rustc 1.0.0", "dir": "licenses/rust-std-1.0.0",
                                  "notice": "COPYRIGHT-library.html"},
                                 {"version": "1.0", "commit": "abc", "dir": "licenses/zenoh-pico"})
        expect("the notices list each linked package with the place of its texts",
               "| dual | 1.2.3 | MIT OR Apache-2.0 | crates.io | `licenses/dual-1.2.3/LICENSE-APACHE`, "
               "`licenses/dual-1.2.3/LICENSE-MIT` |" in notices)
        expect("the notices name the target the graph was read for",
               "for `i686-pc-windows-msvc` (`cargo tree`)" in notices)
        expect("a package with no text is listed under its own heading",
               "## Linked packages that ship no licence text (1)" in notices and "- bare 3.0.0: MIT" in notices)
        expect("the same rows give the same notices",
               notices == render_notices("p", "i686-pc-windows-msvc", rows, [],
                                         {"release": "rustc 1.0.0", "dir": "licenses/rust-std-1.0.0",
                                          "notice": "COPYRIGHT-library.html"},
                                         {"version": "1.0", "commit": "abc", "dir": "licenses/zenoh-pico"}))
        expect("a pipe in a licence cell does not split the table", cell("A | B") == "A \\| B")

        stage = pathlib.Path(tmp) / "out" / "wz-capi-pico-x"
        (stage / "include" / "zenoh-pico").mkdir(parents=True)
        (stage / "include" / "zenoh-pico" / "config.h").write_text("#define X 1\n", encoding="utf-8")
        (stage / "README.md").write_text("read me\n", encoding="utf-8")
        manifest = {"format": FORMAT, "format_version": FORMAT_VERSION, "files": file_rows(stage)}
        (stage / MANIFEST).write_text(render_json(manifest), encoding="utf-8")
        expect("the manifest lists every file but itself, in path order",
               [r["path"] for r in manifest["files"]] == ["README.md", "include/zenoh-pico/config.h"])
        expect("a package as written verifies", verify_findings(stage) == [])

        first = pathlib.Path(tmp) / "a.zip"
        second = pathlib.Path(tmp) / "b.zip"
        write_zip(stage, first, 1700000000)
        write_zip(stage, second, 1700000000)
        expect("the same tree and time give the same zip bytes", first.read_bytes() == second.read_bytes())
        with zipfile.ZipFile(first) as z:
            infos = z.infolist()
            expect("the zip holds the files under the package's name, in path order, and no directory",
                   [i.filename for i in infos] == ["wz-capi-pico-x/README.md",
                                                   "wz-capi-pico-x/include/zenoh-pico/config.h",
                                                   f"wz-capi-pico-x/{MANIFEST}"])
            expect("every entry carries the given time", all(i.date_time == zip_time(1700000000) for i in infos))
        expect("a time before 1980 is the zip format's first second", zip_time(0) == (1980, 1, 1, 0, 0, 0))
        extracted = extract_zip(first, pathlib.Path(tmp) / "x")
        expect("an extracted zip verifies against its manifest", verify_findings(extracted) == [])

        (stage / "README.md").write_text("read me!\n", encoding="utf-8")
        expect("a changed file is a finding", any(f.startswith("README.md: size") for f in verify_findings(stage)))
        (stage / "README.md").write_text("read me\n", encoding="utf-8")
        (stage / "extra.txt").write_text("x", encoding="utf-8")
        expect("a file the manifest does not name is a finding",
               verify_findings(stage) == ["extra.txt: in the package and not in the manifest"])
        (stage / "extra.txt").unlink()
        (stage / "include" / "zenoh-pico" / "config.h").unlink()
        expect("a file the manifest names and the package lacks is a finding",
               verify_findings(stage) == ["include/zenoh-pico/config.h: the manifest names it and the package "
                                          "does not have it"])
        (stage / MANIFEST).write_text(render_json({"format": "other", "format_version": 1, "files": []}),
                                      encoding="utf-8")
        expect("a manifest of another format is a finding", len(verify_findings(stage)) == 1)

        stray = pathlib.Path(tmp) / "stray.zip"
        with zipfile.ZipFile(stray, "w") as z:
            z.writestr("one/a", "a")
            z.writestr("two/b", "b")
        try:
            extract_zip(stray, pathlib.Path(tmp) / "y")
            expect("a zip of two directories is not a package", False)
        except Refusal:
            pass
        climbing = pathlib.Path(tmp) / "climbing.zip"
        with zipfile.ZipFile(climbing, "w") as z:
            z.writestr("pkg/a", "a")
            z.writestr("pkg/../../outside", "b")
        try:
            extract_zip(climbing, pathlib.Path(tmp) / "z")
            expect("a member that climbs out of the extraction directory is refused", False)
        except Refusal:
            pass
        expect("a member under the package's directory extracts under the root",
               extracts_under(pathlib.Path(tmp) / "z", "pkg/include/zenoh-pico.h"))
        expect("an absolute member does not", not extracts_under(pathlib.Path(tmp) / "z", "/etc/passwd"))
        expect("a member that climbs out does not",
               not extracts_under(pathlib.Path(tmp) / "z", "pkg/../../outside"))

    report = "\n".join([
        "warning text",
        json.dumps({"reason": "build-script-executed", "package_id": "path+file:///w/crates/zenoh-pico-sys#0.1.0",
                    "out_dir": "/t/build/zenoh-pico-sys-1/out"}),
        json.dumps({"reason": "compiler-artifact", "target": {"name": "wz_capi_pico", "kind": ["cdylib", "rlib"]},
                    "filenames": ["/t/wz_capi_pico.dll", "/t/wz_capi_pico.dll.lib", "/t/wz_capi_pico.pdb",
                                  "/t/libwz_capi_pico.rlib"]}),
        json.dumps({"reason": "compiler-artifact", "target": {"name": "other", "kind": ["lib"]}, "filenames": ["/t/o"]}),
    ])
    files = artifact_files(report, LIBRARY)
    expect("the DLL, its import library and its symbols are told apart by suffix",
           pick(files, ".dll") == pathlib.Path("/t/wz_capi_pico.dll")
           and pick(files, ".dll.lib") == pathlib.Path("/t/wz_capi_pico.dll.lib")
           and pick(files, ".pdb") == pathlib.Path("/t/wz_capi_pico.pdb"))
    expect("a library the report does not name has no files", artifact_files(report, "absent") == [])
    expect("the installed headers are the build script's out directory",
           pico_include(report) == pathlib.Path("/t/build/zenoh-pico-sys-1/out/include"))
    try:
        pico_include("")
        expect("a report with no header build is refused", False)
    except Refusal:
        pass

    statement = {"digest": "sha256:" + "0" * 64, "engine": "tokio",
                 "capabilities": [{"id": "a", "supported": True}, {"id": "b", "supported": False}],
                 "limits": [{"id": "L", "value": 4, "default": 2}, {"id": "M", "value": 1, "default": 1}],
                 "policies": [{"id": "p", "value": "on", "upstream": "off"}]}
    notes = release_notes("# Notes\n\nwritten\n", {
        "name": "n", "version": "0.1.0", "commit": "c" * 40, "tree_clean": False, "rustc": "rustc 1.0.0",
        "target": "i686-pc-windows-msvc", "profile": "host-peer-ext", "features": ["std", "a"],
        "statement": statement})
    expect("the release notes keep the written part first", notes.startswith("# Notes\n\nwritten\n\n## This build"))
    expect("the release notes name the build's target", "target `i686-pc-windows-msvc`" in notes)
    expect("the release notes name the capabilities the build has and no other", "Capabilities (1): `a`" in notes)
    expect("the release notes name what is off its default, and only that",
           "L = 4 (default 2)" in notes and "M = 1" not in notes and "p = on (upstream off)" in notes)
    expect("a tree with changes says so", "with changes not committed" in notes)
    expect("a build that states no form is the one library", "- Form: one library, `wz_capi_pico.dll`" in notes)
    expect("a build that states no standard library links `std`", "- Rust standard library: linked (`std`)" in notes)
    nostd_notes = release_notes("# Notes\n", {
        "name": "n", "version": "0.1.0", "commit": "c" * 40, "tree_clean": True, "rustc": "rustc 1.0.0",
        "target": "x86_64-pc-windows-msvc", "profile": "host-peer-ext", "features": ["os-windows"],
        "statement": statement, "stdlib": "nostd"})
    expect("the notes of the library without `std` say so and name its form",
           "- Rust standard library: not linked: `core` and `alloc` over the system's own calls (`os-windows`)"
           in nostd_notes)
    split_notes = release_notes("# Notes\n", {
        "name": "n", "version": "0.1.0", "commit": "c" * 40, "tree_clean": True, "rustc": "rustc 1.0.0",
        "target": "x86_64-pc-windows-msvc", "profile": "host-peer-ext", "features": ["std"],
        "statement": statement, "form": "split"})
    expect("the split form's notes name both libraries",
           "`wz_capi_pico.dll`, `wz_capi_pico_ext.dll` (a program links both)" in split_notes)

    expect("the one library's package keeps its name",
           package_name("0.1.0", "p", "x64", "0123456789abc") == "wz-capi-pico-0.1.0-p-windows-x64-0123456789")
    expect("the split package says so in its name",
           package_name("0.1.0", "p", "x86", "0123456789abc", "split")
           == "wz-capi-pico-0.1.0-p-windows-x86-split-0123456789")
    expect("a manifest's form is read", form_of({"form": "split"}) == "split")
    for manifest in ({}, {"form": "double"}):
        try:
            form_of(manifest)
            expect(f"a manifest of form {manifest.get('form')} is refused", False)
        except Refusal:
            pass
    expect("the additional library takes the features it declares, in the list's order",
           ext_features(["std", "engine-tokio", "replay-cache", "unstable-api", "e2e-sender"],
                        {"e2e-sender", "replay-cache", "std", "unstable-api"})
           == ["std", "replay-cache", "unstable-api", "e2e-sender"])
    expect("no option builds every width in the one form without `std`, the form a release ships",
           build_selection([]) == (list(ARCHES), ["single"], "nostd") and DEFAULT_STDLIB in RELEASE_STDLIBS)
    expect("the library with `std` is built in every form, every width when none is named",
           build_selection(["--stdlib", "std"]) == (list(ARCHES), list(FORMS), "std"))
    expect("an option narrows its axis only",
           build_selection(["--stdlib", "std", "--form", "split"]) == (list(ARCHES), ["split"], "std")
           and build_selection(["--form", "single", "--arch", "x86", "--stdlib", "std"])
           == (["x86"], ["single"], "std")
           and build_selection(["--arch", "x86"]) == (["x86"], ["single"], "nostd"))
    expect("the forms of each standard library are the ones a package is made in",
           stdlib_forms("std") == list(FORMS) and stdlib_forms("nostd") == ["single"])
    expect("the library without `std` is built in the one form, every width when none is named",
           build_selection(["--stdlib", "nostd"]) == (list(ARCHES), ["single"], "nostd")
           and build_selection(["--stdlib", "nostd", "--arch", "x64", "--form", "single"])
           == (["x64"], ["single"], "nostd"))
    for options in (["--form"], ["--form", "split", "--form", "single"], ["--arch", "arm64"],
                    ["--form", "double"], ["--target", "x"], ["--stdlib", "alloc"],
                    ["--stdlib", "nostd", "--form", "split"], ["--form", "split"],
                    ["--stdlib", "std", "--stdlib", "nostd"]):
        try:
            build_selection(options)
            expect(f"--build {' '.join(options)} is refused", False)
        except Refusal:
            pass
    expect("no option measures every width, and --arch one",
           measure_selection([]) == list(ARCHES) and measure_selection(["--arch", "x86"]) == ["x86"])
    for options in (["--arch"], ["--arch", "arm64"], ["--form", "single"], ["--arch", "x64", "--arch", "x86"]):
        try:
            measure_selection(options)
            expect(f"--measure {' '.join(options)} is refused", False)
        except Refusal:
            pass
    expect("the size gate's client is measured in both forms, the one without `std` second",
           [case for case, _, _ in SIZE_CASES] == ["pico-client-coop-windows", "pico-client-coop-nostd-windows"]
           and SIZE_CASES[1][1] == "os-windows,link-udp" and NOSTD_PROFILE in SIZE_CASES[1][2])

    table = {"std": [], "engine-coop": ["std", "dep:x"], "engine-tokio": ["std"], "os-windows": ["dep:x"],
             "link-udp": ["x?/link-udp"], "peer": ["link-udp"], "clock-source": ["std"],
             "timed": ["clock-source"]}
    expect("the list without `std` names os-windows for engine-coop, keeps the rest in order, drops std",
           nostd_features(["engine-coop", "std", "peer", "link-udp"], table) == ["os-windows", "peer", "link-udp"])
    for features, word in ((["engine-tokio", "std", "peer"], "engine-coop"),
                           (["engine-coop", "std", "timed"], "timed"),
                           (["engine-coop", "absent"], "absent")):
        try:
            nostd_features(features, table)
            expect(f"a list of {features} is refused", False)
        except Refusal as err:
            expect(f"the refusal of {features} names {word} ({err})", word in str(err))
    expect("the package without `std` says so in its name, after its form",
           package_name("0.1.0", "p", "x64", "0123456789abc", "single", "nostd")
           == "wz-capi-pico-0.1.0-p-windows-x64-nostd-0123456789")
    expect("a manifest's standard library is read", stdlib_of({"stdlib": "nostd"}) == "nostd")
    for manifest in ({}, {"stdlib": "alloc"}):
        try:
            stdlib_of(manifest)
            expect(f"a manifest of standard library {manifest.get('stdlib')} is refused", False)
        except Refusal:
            pass

    def pe_image(rows: list[tuple[bytes, int, int]], optional: int = 0) -> bytes:
        """A PE image of the section rows (name, size in memory, characteristics), its header
        where an MZ header points, as the linker lays one out."""
        image = bytearray(b"MZ" + b"\0" * 0x3E)
        image[0x3C:0x40] = (0x40).to_bytes(4, "little")
        image += b"PE\0\0" + (0x8664).to_bytes(2, "little") + len(rows).to_bytes(2, "little")
        image += b"\0" * 12 + optional.to_bytes(2, "little") + b"\0" * 2 + b"\0" * optional
        for name, size, flags in rows:
            image += name.ljust(8, b"\0") + size.to_bytes(4, "little") + b"\0" * 24 + flags.to_bytes(4, "little")
        return bytes(image)

    image = pe_image([(b".text", 1000, 0x60000020), (b".rdata", 300, 0x40000040), (b".data", 50, 0xC0000040),
                      (b".bss", 20, 0xC0000080), (b".reloc", 8, 0x42000040)], optional=240)
    expect("a PE image's sections are read from its own table, past its optional header",
           pe_sections(image) == [(".text", 1000, 0x60000020), (".rdata", 300, 0x40000040),
                                  (".data", 50, 0xC0000040), (".bss", 20, 0xC0000080), (".reloc", 8, 0x42000040)])
    expect("text is what is loaded read-only, data what is written, bss what is not stored, and the "
           "relocations none of them",
           pe_sizes(image) == {"text": 1300, "data": 50, "bss": 20})
    expect("the size line has the totals, then every section",
           size_line(image) == "text=1300 data=50 bss=20 (.text=1000 .rdata=300 .data=50 .bss=20 .reloc=8)")
    for bad in (b"", b"ZM" + b"\0" * 0x3E, image[:0x40] + b"XX\0\0" + image[0x44:], image[:-10]):
        try:
            pe_sections(bad)
            expect(f"bytes that are no PE image are refused ({len(bad)} bytes)", False)
        except Refusal:
            pass
    two = render_notices("p", "x86_64-pc-windows-msvc", [], [],
                         {"release": "rustc 1.0.0", "dir": "licenses/rust-std-1.0.0",
                          "notice": "COPYRIGHT-library.html"},
                         {"version": "1.0", "commit": "abc", "dir": "licenses/zenoh-pico"},
                         FORMS["split"], (CRATE, EXT_CRATE))
    expect("the split package's notices name both libraries and both graphs",
           "The libraries of this package (`release/bin/wz_capi_pico.dll`" in two
           and "`release/bin/wz_capi_pico_ext.dll`" in two
           and f"`{CRATE}` and `{EXT_CRATE}` built with" in two)
    with tempfile.TemporaryDirectory() as tmp:
        commit = "0123456789abcdef0123456789abcdef01234567"

        def release_dir(rows: list[tuple[str, str, dict]]) -> pathlib.Path:
            """A directory of packages as a release job downloads them: (width, form, what differs)."""
            out = pathlib.Path(tempfile.mkdtemp(dir=tmp))
            for arch, form, differs in rows:
                built = {"commit": differs.get("commit", commit), "tree_clean": differs.get("clean", True)}
                version = differs.get("version", "0.1.0")
                stdlib = differs.get("stdlib", RELEASE_STDLIBS[0])
                name = package_name(version, "p", arch, built["commit"], form, stdlib)
                stage = pathlib.Path(tempfile.mkdtemp(dir=tmp)) / name
                stage.mkdir()
                (stage / "README.md").write_text("r\n", encoding="utf-8")
                manifest = {"format": FORMAT, "format_version": FORMAT_VERSION, "name": name, "version": version,
                            "profile": "p", "target": ARCHES[arch][0], "form": form, "stdlib": stdlib,
                            "built_from": built, "files": file_rows(stage)}
                (stage / MANIFEST).write_text(render_json(manifest), encoding="utf-8")
                archive = out / f"{name}.zip"
                write_zip(stage, archive, 1700000000)
                (out / f"{name}.zip.sha256").write_text(sha256_line(archive), encoding="ascii", newline="\n")
            return out

        released = RELEASE_STDLIBS[0]
        every = [(arch, form, {}) for arch in ARCHES for form in stdlib_forms(released)]
        expect("a release is the library without `std` alone, one package per width",
               RELEASE_STDLIBS == ("nostd",) and every == [(arch, "single", {}) for arch in ARCHES])
        good = release_dir(every)
        findings, sums = release_findings(good, commit, "v0.1.0")
        expect(f"one package of every width and released form, of the release's commit, is a release ({findings})",
               findings == [])
        expect("the sums are every zip's own .zip.sha256 line, in name order",
               sums == "".join(p.read_text(encoding="ascii") for p in sorted(good.glob("*.zip.sha256")))
               and len(sums.splitlines()) == len(every))
        expect("a tag with a suffix names the version", release_findings(good, commit, "v0.1.0-rc1")[0] == [])
        expect("a tag of another version is a finding",
               release_findings(good, commit, "v0.2.0")[0]
               == ["the tag `v0.2.0` does not name version 0.1.0 (v0.1.0 or v0.1.0-<suffix>)"])
        expect("a tag that runs on past the version is a finding", len(release_findings(good, commit, "v0.1.00")[0]) == 1)
        other = "f" * 40
        findings, _ = release_findings(good, other, "v0.1.0")
        expect("packages of another commit are each a finding",
               sum(f.endswith(f"the release is of {other}") for f in findings) == len(every))
        findings, _ = release_findings(release_dir(every[:-1]), commit, "v0.1.0")
        expect("a width and form with no package is named",
               findings == [f"no package of {every[-1][0]} {every[-1][1]} {released}"])
        findings, _ = release_findings(release_dir(every[:-1] + [(every[-1][0], every[-1][1], {"clean": False})]),
                                       commit, "v0.1.0")
        expect("a package built from a tree with changes is a finding",
               len(findings) == 1 and findings[0].endswith("built from a tree with changes not committed"))
        findings, _ = release_findings(release_dir(every[:-1] + [(every[-1][0], every[-1][1], {"version": "0.2.0"})]),
                                       commit, "v0.1.0")
        expect("packages of two versions are a finding, and the tag misses one of them",
               "the packages are of versions 0.1.0, 0.2.0, not one" in findings
               and any(f.startswith("the tag `v0.1.0` does not name version 0.2.0") for f in findings))
        tampered = release_dir(every)
        side = sorted(tampered.glob("*.zip.sha256"))[0]
        side.write_text("0" * 64 + side.read_text(encoding="ascii")[64:], encoding="ascii", newline="\n")
        findings, _ = release_findings(tampered, commit, "v0.1.0")
        expect("a .zip.sha256 that states another digest is a finding",
               findings == [f"{side.name} does not state the sha256 of {side.name[: -len('.sha256')]}"])
        bare = release_dir(every)
        lone = sorted(bare.glob("*.zip"))[0]
        lone.with_name(lone.name + ".sha256").unlink()
        expect("a zip with no .zip.sha256 is a finding",
               release_findings(bare, commit, "v0.1.0")[0] == [f"{lone.name}: no {lone.name}.sha256 beside it"])
        stray = release_dir(every)
        (stray / "gone.zip.sha256").write_text("0" * 64 + "  gone.zip\n", encoding="ascii")
        expect("a .zip.sha256 with no zip is a finding",
               release_findings(stray, commit, "v0.1.0")[0] == ["gone.zip.sha256: no zip of that name beside it"])
        twice = release_dir(every)
        first = sorted(twice.glob("*.zip"))[0]
        copy_name = first.name[: -len(".zip")] + "-copy.zip"
        shutil.copyfile(first, twice / copy_name)
        (twice / f"{copy_name}.sha256").write_text(sha256_line(twice / copy_name), encoding="ascii", newline="\n")
        findings, _ = release_findings(twice, commit, "v0.1.0")
        expect("a second package of one width and form, under another name, is a finding",
               any(f.startswith(f"{copy_name}: its manifest makes it") for f in findings)
               and any(": a second package of " in f for f in findings))
        for arch, form in (("x64", "single"), ("x86", "split")):
            findings, _ = release_findings(release_dir(every + [(arch, form, {"stdlib": "std"})]),
                                           commit, "v0.1.0")
            expect(f"a package with `std` ({arch} {form}) beside a full release is a finding: it is built to "
                   "compare against, and no release carries it",
                   len(findings) == 1 and findings[0].endswith("built std, a form no release carries (nostd)"))
        findings, _ = release_findings(release_dir([(arch, form, {"stdlib": "std"}) for arch in ARCHES
                                                    for form in FORMS]), commit, "v0.1.0")
        expect("the packages with `std` alone are no release: each is a finding, and every released one is missing",
               sum(f.endswith("built std, a form no release carries (nostd)") for f in findings)
               == len(ARCHES) * len(FORMS)
               and f"no package of {', '.join(f'{arch} single {released}' for arch in ARCHES)}" in findings)
        expect("an empty directory names every width and released form", release_findings(
            pathlib.Path(tempfile.mkdtemp(dir=tmp)), commit, "v0.1.0")[0]
            == ["no package of " + ", ".join(f"{arch} {form} {released}" for arch in ARCHES
                                             for form in stdlib_forms(released))])

    # A pipe read as text without a stated encoding is decoded with the host's code page, which on a
    # Windows runner is not the UTF-8 the tools write: every read of a tool here names its encoding.
    import ast
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    undecoded = [node.lineno for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr in ("run", "check_output", "Popen")
                 and any(k.arg in ("text", "universal_newlines") for k in node.keywords)
                 and not any(k.arg == "encoding" for k in node.keywords)]
    expect(f"every pipe this script reads as text states its encoding (lines {undecoded})", not undecoded)

    for failure in failures:
        print(f"  pico_windows_package selftest FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("  pico_windows_package selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[1] == "--selftest":
            return selftest()
        if len(argv) >= 5 and argv[1] == "--build" and argv[3] == "--profile":
            arches, forms, stdlib = build_selection(argv[5:])
            out = pathlib.Path(argv[2]).resolve()
            out.mkdir(parents=True, exist_ok=True)
            for arch in arches:
                for form in forms:
                    build(out, argv[4], arch, form, stdlib)
            return 0
        if len(argv) >= 2 and argv[1] == "--measure":
            for arch in measure_selection(argv[2:]):
                measure(arch)
            return 0
        if len(argv) == 3 and argv[1] == "--verify":
            target = pathlib.Path(argv[2])
            with tempfile.TemporaryDirectory() as tmp:
                directory = extract_zip(target, pathlib.Path(tmp)) if target.is_file() else target
                findings = verify_findings(directory)
            for finding in findings:
                print(f"  pico-package verify: {finding}", file=sys.stderr)
            print(f"  pico-package verify: {target.name}: {'FAIL' if findings else 'OK'}")
            return 1 if findings else 0
        if len(argv) == 3 and argv[1] == "--test":
            return test(pathlib.Path(argv[2]))
        if len(argv) == 4 and argv[1] == "--release":
            directory = pathlib.Path(argv[2])
            findings, sums = release_findings(directory, git("rev-parse", "HEAD"), argv[3])
            for finding in findings:
                print(f"  pico-package release: {finding}", file=sys.stderr)
            if findings:
                print(f"  pico-package release: {argv[3]}: FAIL")
                return 1
            (directory / SUMS).write_text(sums, encoding="ascii", newline="\n")
            print(f"  pico-package release: {argv[3]}: {len(sums.splitlines())} packages, {SUMS} written: OK")
            return 0
    except Refusal as err:
        print(f"  pico-package REFUSED: {err}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

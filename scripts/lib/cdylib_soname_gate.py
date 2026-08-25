#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2103 (no register item) — every cdylib this workspace emits must carry a SONAME.

Closes item 521 of the unregistered register, filed 2026-08-25 from a
downstream C/C++ consumer's report plus a probe; that register lives outside
this repository, which is why the citation above reads "no register item"
rather than naming a store row that does not exist.

## The defect

Cargo emits a `cdylib` with no `DT_SONAME`, and the ELF rule is then that the
linker writes into the CONSUMER's `DT_NEEDED` whatever string it used to find
the library. Link by PATH -- which is exactly what CMake's
`target_link_libraries(app /abs/path/lib.so)` generates, the ordinary way to
consume a prebuilt `.so` -- and the string is that absolute build-tree path.
Measured on this tree before the fix:

    $ cc probe.c .../crates/target/release/libwz_capi_dissect.so -o probe
    $ readelf -d probe | grep NEEDED
      (NEEDED)  Shared library: [/home/.../crates/target/release/libwz_capi_dissect.so]

That consumer cannot ship what it built. An absolute `DT_NEEDED` is not a
search key: the dynamic linker OPENS it, so `RPATH`, `$ORIGIN` and
`LD_LIBRARY_PATH` are never consulted. The downstream consumer was carrying
`patchelf --set-soname` over every copy it took, which is a cost paid again by
every consumer there will ever be.

## Why the population is DERIVED

The report named four libraries. This workspace emits FIVE -- it did not know
about `wz-volume-example` -- so a gate written from that list would have been
wrong on the day it was written, and would go wrong again the next time a
crate gains `crate-type = ["cdylib"]`. The population here comes from
`cargo metadata`, i.e. cargo's own parse of which targets are cdylibs, and an
EMPTY population is a FAILURE: a gate that cannot find its subjects must not
report green.

## Why the SONAME is read from the ARTIFACT

Neither half is parsed out of source text. The library list comes from cargo
and the SONAME comes from `readelf -d` over the linked `.so`, which is the
thing a consumer actually links. A gate that grepped `build.rs` for
`-Wl,-soname` would be checking the same line the author just wrote, against
itself -- and would not notice a name that disagrees with the file cargo
produced, which is the one mistake the build script cannot catch on its own
(there is no environment variable for a lib TARGET name, so
`wz_cdylib_build::emit_soname` has to be told, and this is where being told
wrong shows up).

## The profile

The dev profile by default, and that is not a weakening: a SONAME is a linker
argument recorded in the dynamic section, with no profile-dependent path
through `wz_cdylib_build` and nothing LTO can remove. Release is available
(`--profile release`) for a lane that wants the shipped artifact, and costs
several minutes because this workspace's release profile is `lto = "thin"`
with `codegen-units = 1`.

## Usage

    python3 scripts/lib/cdylib_soname_gate.py              # gate; non-zero on violation
    python3 scripts/lib/cdylib_soname_gate.py --report     # print the table, always 0
    python3 scripts/lib/cdylib_soname_gate.py --profile release
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

MANIFEST = Path("crates/Cargo.toml")

# The gate reads ELF. Everywhere else it has nothing to say -- and nothing in
# this workspace builds a cdylib for a non-ELF platform, so a run there is a
# provisioning fact rather than a defect. `WZ_SONAME_REQUIRE` turns that SKIP
# into a FAIL, the same arming rule Layers A3/A4/A5/Qz use: a lane that SKIPs
# where the job provisions its input is a provisioning regression wearing a
# green badge.
ELF_PLATFORMS = ("linux", "freebsd", "netbsd", "openbsd", "sunos")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def cdylib_targets() -> list[tuple[str, str]]:
    """`(package name, lib target name)` for every cdylib in the workspace.

    From `cargo metadata`, i.e. cargo's OWN parse -- never a regex over
    Cargo.toml, which cannot tell a `crate-type` key from the same words in a
    comment and cannot resolve a `[lib] name` that differs from the package's.
    """
    proc = _run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(MANIFEST),
        ]
    )
    if proc.returncode != 0:
        print(
            f"cdylib-soname gate FAIL: `cargo metadata` failed (rc={proc.returncode})\n"
            f"{proc.stderr}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    found: list[tuple[str, str]] = []
    for pkg in json.loads(proc.stdout)["packages"]:
        for target in pkg["targets"]:
            if "cdylib" in target["crate_types"]:
                found.append((pkg["name"], target["name"]))
    return sorted(found)


def build(packages: list[str], profile: str) -> dict[str, list[str]]:
    """Build the cdylibs and return, per package, the files cargo says it made.

    `--message-format=json` rather than a constructed path: cargo knows where it
    put the artifact, and a gate that reconstructed
    `crates/target/<profile>/lib<name>.so` would be reimplementing the target
    directory layout -- including the `debug`-for-`dev` special case that has
    caught out every script that has ever guessed it.
    """
    cmd = ["cargo", "build", "--manifest-path", str(MANIFEST), "--message-format=json"]
    if profile != "dev":
        cmd += ["--profile", profile]
    for pkg in packages:
        cmd += ["-p", pkg]

    proc = _run(cmd)
    if proc.returncode != 0:
        print(
            f"cdylib-soname gate FAIL: the cdylib build failed (rc={proc.returncode})\n"
            f"{proc.stderr}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    artifacts: dict[str, list[str]] = {}
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        # `package_id` is an opaque spec whose SHAPE has changed across cargo
        # releases (path+file://… then a bare name@version). The target name is
        # the stable join, and it is what this gate keys on everywhere else.
        name = msg.get("target", {}).get("name")
        if name and "cdylib" in msg.get("target", {}).get("crate_types", []):
            artifacts.setdefault(name, []).extend(
                f for f in msg.get("filenames", []) if f.endswith(".so")
            )
    return artifacts


def soname(path: str) -> str | None:
    """The `DT_SONAME` recorded in an ELF shared object, or None if it has none."""
    proc = _run(["readelf", "-d", path])
    if proc.returncode != 0:
        print(
            f"cdylib-soname gate FAIL: readelf could not read {path}\n{proc.stderr}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    for line in proc.stdout.splitlines():
        if "(SONAME)" in line and "[" in line:
            return line[line.index("[") + 1 : line.rindex("]")]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the table and always exit 0",
    )
    parser.add_argument(
        "--profile",
        default="dev",
        help="cargo profile to build and read (default: dev; see the module doc)",
    )
    args = parser.parse_args()

    if not MANIFEST.is_file():
        # A gate that cannot read its input must not report green.
        print(
            f"cdylib-soname gate FAIL: {MANIFEST} not found (wrong cwd?)",
            file=sys.stderr,
        )
        return 1

    required = os.environ.get("WZ_SONAME_REQUIRE", "") not in ("", "0")
    if sys.platform not in ELF_PLATFORMS:
        msg = f"this platform is {sys.platform!r}, whose shared objects are not ELF"
        if required:
            print(f"cdylib-soname gate FAIL: {msg} (WZ_SONAME_REQUIRE set)", file=sys.stderr)
            return 1
        print(f"cdylib-soname gate SKIP: {msg}")
        return 0
    if shutil.which("readelf") is None:
        print(
            "cdylib-soname gate FAIL: readelf is absent, so no SONAME can be read. "
            "This is a FAIL and not a SKIP because a gate that cannot read its "
            "input must not report green.",
            file=sys.stderr,
        )
        return 1

    targets = cdylib_targets()
    if not targets:
        print(
            "cdylib-soname gate FAIL: cargo metadata reported NO cdylib target. "
            "This workspace has five; either the manifest broke or this gate's "
            "derivation has drifted, and in both cases it just asserted nothing.",
            file=sys.stderr,
        )
        return 1

    artifacts = build([pkg for pkg, _ in targets], args.profile)

    rows: list[tuple[str, str, str, str]] = []
    findings: list[str] = []
    for pkg, lib in targets:
        want = f"lib{lib}.so"
        files = artifacts.get(lib, [])
        if not files:
            findings.append(
                f"{pkg}: cargo built no .so for lib target `{lib}` — the gate "
                f"has nothing to read, which is not the same as a pass"
            )
            rows.append((pkg, lib, want, "<no artifact>"))
            continue
        for path in sorted(set(files)):
            got = soname(path)
            rows.append((pkg, lib, want, got or "<none>"))
            if got is None:
                findings.append(
                    f"{pkg}: {path} carries NO SONAME. A consumer that links it "
                    f"by path records that absolute path in its own DT_NEEDED and "
                    f"cannot redistribute what it built. Add a build.rs calling "
                    f"`wz_cdylib_build::emit_soname(\"{lib}\")` and a "
                    f"`[build-dependencies] wz-cdylib-build` on it."
                )
            elif got != want:
                findings.append(
                    f"{pkg}: {path} says SONAME `{got}`, but cargo named the file "
                    f"`{want}`. A consumer would record a name no file on disk "
                    f"has. Fix the argument to `wz_cdylib_build::emit_soname`."
                )

    width = max(len(r[0]) for r in rows)
    for pkg, _lib, want, got in rows:
        mark = "ok  " if got == want else "FAIL"
        print(f"  {mark} {pkg:<{width}}  soname={got}")
    print(
        f"cdylib-soname: {len(rows)} artifact(s) from {len(targets)} cdylib crate(s), "
        f"profile={args.profile}, {len(findings)} finding(s)"
    )

    if args.report:
        return 0
    if findings:
        print("cdylib-soname gate FAIL:", file=sys.stderr)
        for f in findings:
            print(f"    - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

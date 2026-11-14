#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4483 (no register item) -- `install-zenoh-c.sh --inputs` lists what an
install run would fetch, and fetches, installs and writes nothing.

A host that fetches every release input once into its own content-addressed
cache asks the installer what to fetch rather than keeping its own copy of the
target mapping, the URL filling and the "already installed" tests. The listing
is a contract (the script's header states it), so this drives the real script
and compares its output byte for byte:

  * nothing installed -> one fetch line for the archive and one for the
    source, with the pin's digests and the URLs filled for the host target;
  * both installed -> two `installed` lines naming where;
  * a version override -> `-` digests, or the digests the override brings;
  * what the caller hands in does not change the listing;
  * every refusal an install run makes before fetching (an arch with no
    archive, a pin key missing, an installed tree or header at another
    version, an argument the script does not take) fails the listing and
    prints no line.

Every run happens in a throwaway directory holding HOME, TMPDIR, the prefix and
the checkout, with `curl`, `wget` and `git` on PATH as stubs that record a call
and fail, and `uname` as a stub naming the arch. After each run the directory
is compared with what it held before: a listing that created a directory, a
temp dir or a fetch shows up as a difference. Most cases run a copy of the
script beside a fixture pin, so that the expected lines are literal; one runs
the script in the tree against the shipped pin.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/install-zenoh-c.sh"
PIN = ROOT / "scripts/zenoh-c-oracle.pin"

FAILURES: list[str] = []

X86_DIGEST = "a" * 64
ARM_DIGEST = "b" * 64
SOURCE_DIGEST = "c" * 64

FIXTURE_PIN = (
    "# a fixture pin; the keys are the shipped file's, the values are not\n"
    "ZENOH_C_VERSION=9.9.9\n"
    "ZENOH_C_ARCHIVE=zc-@VERSION@-@TARGET@.zip\n"
    "ZENOH_C_RELEASE_URL=https://example.invalid/release/@VERSION@/@ARCHIVE@\n"
    f"ZENOH_C_SHA256_x86_64-unknown-linux-gnu={X86_DIGEST}\n"
    f"ZENOH_C_SHA256_aarch64-unknown-linux-gnu={ARM_DIGEST}\n"
    "ZENOH_C_SOURCE_URL=https://example.invalid/source/@VERSION@.tar.gz\n"
    f"ZENOH_C_SOURCE_SHA256={SOURCE_DIGEST}\n"
)

X86_URL = "https://example.invalid/release/9.9.9/zc-9.9.9-x86_64-unknown-linux-gnu.zip"
ARM_URL = "https://example.invalid/release/9.9.9/zc-9.9.9-aarch64-unknown-linux-gnu.zip"
SOURCE_URL = "https://example.invalid/source/9.9.9.tar.gz"

UNAME_STUB = """#!/bin/sh
if [ "$1" = "-m" ]; then
    printf '%s\\n' "$SELFTEST_UNAME_M"
    exit 0
fi
exit 1
"""

# A network tool the listing must never call: the call is recorded inside the
# sandbox, so it shows up in the before/after comparison too.
NETWORK_STUB = """#!/bin/sh
printf '%s\\n' "$0 $*" >> "$SELFTEST_CALLS"
exit 1
"""


class Sandbox:
    """One throwaway root: the stubs, HOME, TMPDIR, the prefix and the checkout."""

    def __init__(self, root: Path, pin: str | None) -> None:
        self.root = root
        self.stubs = root / "stubs"
        self.home = root / "home"
        self.tmpdir = root / "tmp"
        self.prefix = root / "prefix"
        self.ref = root / "ref"
        self.calls = root / "calls.log"
        for path in (self.stubs, self.home, self.tmpdir):
            path.mkdir()
        self._stub("uname", UNAME_STUB)
        for tool in ("curl", "wget", "git"):
            self._stub(tool, NETWORK_STUB)
        if pin is None:
            self.script = INSTALLER
        else:
            scripts = root / "repo" / "scripts"
            scripts.mkdir(parents=True)
            self.script = scripts / INSTALLER.name
            self.script.write_bytes(INSTALLER.read_bytes())
            (scripts / PIN.name).write_text(pin, encoding="utf-8")

    def _stub(self, name: str, body: str) -> None:
        path = self.stubs / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def install_libs(self, version: str) -> None:
        (self.prefix / "include").mkdir(parents=True)
        (self.prefix / "lib").mkdir(parents=True)
        (self.prefix / "include" / "zenoh.h").write_text("/* fixture */\n", encoding="utf-8")
        (self.prefix / "include" / "zenoh_configure.h").write_text(
            f'#define ZENOH_C "{version}"\n#define Z_FEATURE_UNSTABLE_API\n', encoding="utf-8")
        (self.prefix / "lib" / "libzenohc.so").write_bytes(b"\x7fELF fixture\n")

    def install_source(self, version: str) -> None:
        (self.ref / "examples").mkdir(parents=True)
        (self.ref / "examples" / "z_put.c").write_text("/* fixture */\n", encoding="utf-8")
        (self.ref / "version.txt").write_text(version + "\n", encoding="utf-8")

    def snapshot(self) -> dict[str, bytes | None]:
        """Every path under the root, a file with its bytes, a directory as None."""
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes() if path.is_file() else None
            for path in sorted(self.root.rglob("*"))
        }

    def run(self, *args: str, arch: str = "x86_64",
            extra: dict[str, str] | None = None) -> tuple[int, str, str, list[str]]:
        """`(rc, stdout, stderr, what changed under the root)`."""
        env = {
            "PATH": f"{self.stubs}:/usr/bin:/bin",
            "HOME": str(self.home),
            "TMPDIR": str(self.tmpdir),
            "WZ_ZENOH_C_PREFIX": str(self.prefix),
            "WZ_ZENOH_C_REF": str(self.ref),
            "SELFTEST_UNAME_M": arch,
            "SELFTEST_CALLS": str(self.calls),
        }
        env.update(extra or {})
        before = self.snapshot()
        proc = subprocess.run(["bash", str(self.script), *args], env=env,
                              capture_output=True, text=True, cwd=self.root)
        after = self.snapshot()
        changed = sorted(key for key in before.keys() | after.keys()
                         if before.get(key, 0) != after.get(key, 0))
        return proc.returncode, proc.stdout, proc.stderr, changed


def listed(name: str, got: tuple[int, str, str, list[str]], want: str) -> None:
    """A listing that succeeded with exactly `want` on stdout and nothing else."""
    rc, out, err, changed = got
    if rc != 0:
        FAILURES.append(f"{name}: rc {rc}, wanted 0\n{out}{err}")
    elif out != want:
        FAILURES.append(f"{name}: stdout\n{out!r}\nwanted\n{want!r}")
    elif err:
        FAILURES.append(f"{name}: stderr is not empty\n{err}")
    if changed:
        FAILURES.append(f"{name}: the run changed {changed}")


def refused(name: str, got: tuple[int, str, str, list[str]], needle: str) -> None:
    """A run that failed, said `needle`, printed no listing line, and wrote nothing."""
    rc, out, err, changed = got
    if rc == 0:
        FAILURES.append(f"{name}: rc 0, wanted a failure\n{out}{err}")
    if needle not in out + err:
        FAILURES.append(f"{name}: output lacks {needle!r}\n{out}{err}")
    lines = [line for line in out.splitlines()
             if line.endswith((" WZ_ZENOH_C_ARCHIVE", " WZ_ZENOH_C_SOURCE"))]
    if lines:
        FAILURES.append(f"{name}: a refusal printed listing lines {lines}")
    if changed:
        FAILURES.append(f"{name}: the run changed {changed}")


def pin_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, value)
    return values


def fixture(make) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        make(Path(tmp))


def main() -> int:
    if len(sys.argv) != 1:
        print(f"install-zenoh-c inputs selftest: FAIL unknown arguments {sys.argv[1:]}")
        return 2
    for path in (INSTALLER, PIN):
        if not path.is_file():
            print(f"install-zenoh-c inputs selftest: FAIL {path} is missing")
            return 1

    def fresh(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        listed("nothing installed, x86_64", box.run("--inputs"),
               f"{X86_DIGEST} {X86_URL} WZ_ZENOH_C_ARCHIVE\n"
               f"{SOURCE_DIGEST} {SOURCE_URL} WZ_ZENOH_C_SOURCE\n")
        listed("nothing installed, aarch64", box.run("--inputs", arch="aarch64"),
               f"{ARM_DIGEST} {ARM_URL} WZ_ZENOH_C_ARCHIVE\n"
               f"{SOURCE_DIGEST} {SOURCE_URL} WZ_ZENOH_C_SOURCE\n")
        listed("inputs handed in do not change the listing",
               box.run("--inputs", extra={"WZ_ZENOH_C_ARCHIVE": str(tmp / "absent.zip"),
                                          "WZ_ZENOH_C_SOURCE": str(tmp / "absent")}),
               f"{X86_DIGEST} {X86_URL} WZ_ZENOH_C_ARCHIVE\n"
               f"{SOURCE_DIGEST} {SOURCE_URL} WZ_ZENOH_C_SOURCE\n")
        listed("a digest variable at the pinned version is the one held to",
               box.run("--inputs", extra={"WZ_ZENOH_C_SHA256": "d" * 64}),
               f"{'d' * 64} {X86_URL} WZ_ZENOH_C_ARCHIVE\n"
               f"{SOURCE_DIGEST} {SOURCE_URL} WZ_ZENOH_C_SOURCE\n")
        listed("a version override without digests lists `-`",
               box.run("--inputs", extra={"ZENOH_C_VERSION": "9.9.10"}),
               "- https://example.invalid/release/9.9.10/zc-9.9.10-x86_64-unknown-linux-gnu.zip"
               " WZ_ZENOH_C_ARCHIVE\n"
               "- https://example.invalid/source/9.9.10.tar.gz WZ_ZENOH_C_SOURCE\n")
        listed("a version override lists the digests it brings",
               box.run("--inputs", extra={"ZENOH_C_VERSION": "9.9.10",
                                          "WZ_ZENOH_C_SHA256": "e" * 64,
                                          "WZ_ZENOH_C_SOURCE_SHA256": "f" * 64}),
               f"{'e' * 64} https://example.invalid/release/9.9.10/"
               "zc-9.9.10-x86_64-unknown-linux-gnu.zip WZ_ZENOH_C_ARCHIVE\n"
               f"{'f' * 64} https://example.invalid/source/9.9.10.tar.gz WZ_ZENOH_C_SOURCE\n")
        refused("an arch with no published archive", box.run("--inputs", arch="riscv64"),
                "FAIL: no published zenoh-c archive for arch riscv64")
        refused("an unknown argument", box.run("--input"), "FAIL: unknown arguments: --input")
        refused("a second argument", box.run("--inputs", "extra"),
                "FAIL: unknown arguments: --inputs extra")
        if box.calls.exists():
            FAILURES.append(f"a network tool was called: {box.calls.read_text()}")

    def installed(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        box.install_libs("9.9.9")
        box.install_source("9.9.9")
        listed("both installed", box.run("--inputs"),
               f"installed {box.prefix} WZ_ZENOH_C_ARCHIVE\n"
               f"installed {box.ref} WZ_ZENOH_C_SOURCE\n")
        # An install run never asks the arch when the archive is installed.
        listed("both installed, an arch with no archive", box.run("--inputs", arch="riscv64"),
               f"installed {box.prefix} WZ_ZENOH_C_ARCHIVE\n"
               f"installed {box.ref} WZ_ZENOH_C_SOURCE\n")

    def libs_only(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        box.install_libs("9.9.9")
        listed("archive installed, source not", box.run("--inputs"),
               f"installed {box.prefix} WZ_ZENOH_C_ARCHIVE\n"
               f"{SOURCE_DIGEST} {SOURCE_URL} WZ_ZENOH_C_SOURCE\n")

    def source_only(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        box.install_source("9.9.9")
        listed("source installed, archive not", box.run("--inputs"),
               f"{X86_DIGEST} {X86_URL} WZ_ZENOH_C_ARCHIVE\n"
               f"installed {box.ref} WZ_ZENOH_C_SOURCE\n")

    def stale_checkout(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        box.install_libs("9.9.9")
        box.install_source("9.9.8")
        refused("an installed checkout at another version", box.run("--inputs"),
                "'9.9.8', not the pinned 9.9.9.")

    def stale_header(tmp: Path) -> None:
        box = Sandbox(tmp, FIXTURE_PIN)
        box.install_libs("9.9.8")
        box.install_source("9.9.9")
        refused("an installed header at another version", box.run("--inputs"),
                "FAIL: installed zenoh-c is '9.9.8', expected 9.9.9.")

    def missing_key(tmp: Path) -> None:
        pin = "".join(line + "\n" for line in FIXTURE_PIN.splitlines()
                      if not line.startswith("ZENOH_C_SHA256_aarch64"))
        box = Sandbox(tmp, pin)
        refused("a target with no digest key", box.run("--inputs", arch="aarch64"),
                "has no ZENOH_C_SHA256_aarch64-unknown-linux-gnu")
        nourl = "".join(line + "\n" for line in FIXTURE_PIN.splitlines()
                        if not line.startswith("ZENOH_C_SOURCE_URL="))
        (box.script.parent / PIN.name).write_text(nourl, encoding="utf-8")
        refused("a pin with no source URL", box.run("--inputs"), "has no ZENOH_C_SOURCE_URL")

    def shipped_pin(tmp: Path) -> None:
        pin = pin_values(PIN.read_text(encoding="utf-8"))
        box = Sandbox(tmp, None)
        for arch, target in (("x86_64", "x86_64-unknown-linux-gnu"),
                             ("aarch64", "aarch64-unknown-linux-gnu")):
            archive = (pin["ZENOH_C_ARCHIVE"].replace("@VERSION@", pin["ZENOH_C_VERSION"])
                       .replace("@TARGET@", target))
            url = (pin["ZENOH_C_RELEASE_URL"].replace("@VERSION@", pin["ZENOH_C_VERSION"])
                   .replace("@ARCHIVE@", archive))
            source = pin["ZENOH_C_SOURCE_URL"].replace("@VERSION@", pin["ZENOH_C_VERSION"])
            listed(f"the shipped pin, {arch}", box.run("--inputs", arch=arch),
                   f"{pin['ZENOH_C_SHA256_' + target]} {url} WZ_ZENOH_C_ARCHIVE\n"
                   f"{pin['ZENOH_C_SOURCE_SHA256']} {source} WZ_ZENOH_C_SOURCE\n")

    for make in (fresh, installed, libs_only, source_only, stale_checkout, stale_header,
                 missing_key, shipped_pin):
        fixture(make)

    if FAILURES:
        print(f"install-zenoh-c inputs selftest: FAIL ({len(FAILURES)} case(s))")
        for failure in FAILURES:
            print("  - " + failure.replace("\n", "\n    "))
        return 1
    print("install-zenoh-c inputs selftest: OK (fetch, installed, override and refused listings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

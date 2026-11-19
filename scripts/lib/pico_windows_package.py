#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4551 (no register item) -- the Windows x64 release package of the pico C ABI library.

    pico_windows_package.py --build OUT --profile ID
    pico_windows_package.py --verify DIR|ZIP
    pico_windows_package.py --test ZIP
    pico_windows_package.py --selftest

`--build` makes, on a Windows host with the MSVC toolchain, one package of `wz-capi-pico` built from
a registered profile (`configs/profiles/<ID>.conf`, resolved strictly by the pinned Kconfig
interpreter, as `wz_config.py --resolve-features pico` resolves it): the DLL in a debug and a release
build, each with its import library and its symbols, the headers a program compiles against, the
examples, a configuration sample, the usage notes and release notes, the licence of the library and
the notices of everything it links, and `manifest.json`, the size and SHA-256 of every other file.
It writes `OUT/<name>/`, `OUT/<name>.zip` and `OUT/<name>.zip.sha256`.

`--verify` re-hashes a package (a directory, or a zip it extracts first) against its manifest: a
file that differs, one the manifest names that is missing, and one it does not name are each a
finding. `--test` is the regression test of a zip on a Windows host: it extracts and verifies it,
then compiles every example and `crates/wz-capi-pico/tests/c/package_check.c` against the package's
own `include/` and import library with MSVC's `cl`, for the debug and the release build, and runs
each with the package's `bin/` on the path. The check program holds the DLL to the conformance
digest of the package's `build-statement.json` and reads the configuration sample through it.

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
TARGET = "x86_64-pc-windows-msvc"
CRATE = "wz-capi-pico"
LIBRARY = "wz_capi_pico"
PROFILE_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FORMAT = "wz-pico-windows-package"
FORMAT_VERSION = 1
MANIFEST = "manifest.json"
STATEMENT = "build-statement.json"

# The two builds a package carries: (directory in the package, cargo's profile arguments).
BUILDS = (("release", ["--release"]), ("debug", []))
# Full debug information in both builds: the symbols are in the PDB beside the DLL, not in it.
DEBUG_INFO_ENV = {"CARGO_PROFILE_DEV_DEBUG": "full", "CARGO_PROFILE_RELEASE_DEBUG": "full"}
# Given to the link of the DLL alone (`cargo rustc`), so no dependency is rebuilt for them.
LINK_ARGS = ["-C", "link-arg=/Brepro", "-C", "link-arg=/PDBALTPATH:%_PDB%"]
# The variables a build reads its limits and policies from; the profile states them, nobody else.
STATED_PREFIXES = ("WZ_LIMIT_", "WZ_POLICY_")

PACKAGE_DOCS = CRATES / CRATE / "package"
EXAMPLES_DIR = CRATES / CRATE / "examples" / "c"
# The program the C ABI examples job runs as the example of a transport the program supplies.
TRANSPORT_EXAMPLE = CRATES / CRATE / "tests" / "c" / "pico_app_transport.c"
CHECK_PROGRAM = CRATES / CRATE / "tests" / "c" / "package_check.c"
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


def package_name(version: str, profile: str, commit: str) -> str:
    return f"{CRATE}-{version}-{profile}-windows-x64-{commit[:10]}"


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


def render_notices(profile: str, linked: list[dict], compile_time: list[dict], rust: dict, pico: dict) -> str:
    """THIRD-PARTY-NOTICES.md: what the library links and the texts that cover it."""
    textless = [row for row in linked if not row["texts"]]
    out = [
        "# Third-party notices",
        "",
        "The library of this package (`release/bin/wz_capi_pico.dll` and `debug/bin/wz_capi_pico.dll`) is",
        "watching-zenoh, under the licence in `LICENSE` or a commercial licence (`LICENSE-COMMERCIAL.md`).",
        "It links the packages listed below, each under its own licence.",
        "",
        "This list is derived from the build, not written by hand: it is the normal-dependency graph of",
        f"`{CRATE}` built with the features of profile `{profile}` for `{TARGET}` (`cargo tree`),",
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


def extract_zip(archive: pathlib.Path, into: pathlib.Path) -> pathlib.Path:
    """Extract a package zip and return its one top directory; a zip of anything else is refused."""
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        tops = {name.split("/", 1)[0] for name in names}
        if len(tops) != 1 or any(".." in pathlib.PurePosixPath(n).parts or n.startswith("/") for n in names):
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
    out = [
        template.rstrip("\n"),
        "",
        "## This build",
        "",
        f"- Package: `{facts['name']}`",
        f"- Library version: {facts['version']}",
        f"- Source: commit `{facts['commit']}`" + ("" if facts["tree_clean"] else " with changes not committed"),
        f"- Toolchain: `{facts['rustc']}`, target `{TARGET}`",
        f"- Profile: `{facts['profile']}` (`configs/profiles/{facts['profile']}.conf`)",
        f"- Conformance digest: `{statement['digest']}` (what `wz_ext_conformance_digest()` answers)",
        f"- Engine: {statement['engine']}",
        f"- Capabilities ({len(on)}): " + ", ".join(f"`{c}`" for c in on),
        "- Limits off their default: " + ("; ".join(limits) if limits else "none"),
        "- Policies off upstream's: " + ("; ".join(policies) if policies else "none"),
        f"- Cargo features: `{','.join(facts['features'])}`",
        "",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# The build (a Windows host with the MSVC toolchain)
# ---------------------------------------------------------------------------


def run(cmd: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> str:
    print("+ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, text=True)
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
    except wz_config.PresetError as err:
        raise Refusal(f"profile {profile} does not resolve: {err}") from err
    features = wz_config.features_for(decl, "pico", wz_config.resolved_caps(decl, kconf))
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


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()


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


def build(out: pathlib.Path, profile: str) -> pathlib.Path:
    if sys.platform != "win32":
        raise Refusal("the package is built on a Windows host: its DLL, import library and symbols are "
                      "the MSVC toolchain's")
    stated = stated_in_environment(dict(os.environ))
    if stated:
        raise Refusal(f"the environment states {', '.join(stated)}; the package's build is its profile's "
                      "alone, so unset them")
    decl = wz_config.load_decl()
    plan = resolve_profile(decl, profile)
    features = plan["features"]
    header = arm_header(decl, features, plan["env"])
    env = {**os.environ, **plan["env"], **DEBUG_INFO_ENV}

    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--all-features",
                               "--filter-platform", TARGET], CRATES))
    crate = next((p for p in metadata["packages"] if p["name"] == CRATE and p["id"] in metadata["workspace_members"]),
                 None)
    if crate is None:
        raise Refusal(f"{CRATE} is no package of the crates workspace")
    commit = git("rev-parse", "HEAD")
    name = package_name(crate["version"], profile, commit)
    stage = out / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    include = pico_include(run(["cargo", "build", "-p", "zenoh-pico-sys", "--message-format=json-render-diagnostics"],
                               CRATES, env))
    for src in sorted(p for p in include.rglob("*") if p.is_file()):
        copy(src, stage / "include" / src.relative_to(include))
    (stage / "include" / "zenoh-pico" / "config.h").write_text(header, encoding="utf-8", newline="\n")

    feature_args = ["--no-default-features", "--features", ",".join(features)]
    for where, cargo_profile in BUILDS:
        report = run(["cargo", "rustc", "-p", CRATE, "--lib", *feature_args, *cargo_profile,
                      "--message-format=json-render-diagnostics", "--", *LINK_ARGS], CRATES, env)
        files = artifact_files(report, LIBRARY)
        dll = pick(files, ".dll")
        if dll is None:
            raise Refusal(f"cargo reported no single DLL of {CRATE} for the {where} build: {files}")
        # The linker writes the import library and the symbols beside the DLL, by its name, whether
        # or not cargo lists them; `copy` refuses one that is not there.
        implib = pick(files, ".dll.lib") or dll.parent / f"{dll.name}.lib"
        pdb = pick(files, ".pdb") or dll.with_suffix(".pdb")
        copy(dll, stage / where / "bin" / f"{LIBRARY}.dll")
        copy(pdb, stage / where / "bin" / f"{LIBRARY}.pdb")
        copy(implib, stage / where / "lib" / f"{LIBRARY}.lib")

    for rel, src in FIXED_FILES:
        copy(src, stage / rel)
    for src in sorted(p for p in EXAMPLES_DIR.iterdir() if p.is_file()):
        copy(src, stage / "examples" / src.name)
    copy(TRANSPORT_EXAMPLE, stage / "examples" / TRANSPORT_EXAMPLE.name)
    (stage / STATEMENT).write_text(render_json(plan["statement"]), encoding="utf-8", newline="\n")

    tree_args = ["cargo", "tree", "-p", CRATE, *feature_args, "--target", TARGET, "--prefix", "none", "--format", "{p}"]
    linked_ids = parse_tree(run(tree_args + ["-e", "normal,no-proc-macro"], CRATES, env))
    all_ids = parse_tree(run(tree_args + ["-e", "normal"], CRATES, env))
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
    (stage / "THIRD-PARTY-NOTICES.md").write_text(render_notices(profile, linked, compile_time, rust, pico),
                                                  encoding="utf-8", newline="\n")

    tree_clean = git("status", "--porcelain", "--untracked-files=no") == ""
    facts = {"name": name, "version": crate["version"], "commit": commit, "tree_clean": tree_clean,
             "rustc": rust["release"], "profile": profile, "features": features, "statement": plan["statement"]}
    template = (PACKAGE_DOCS / "RELEASE-NOTES.md").read_text(encoding="utf-8")
    (stage / "RELEASE-NOTES.md").write_text(release_notes(template, facts), encoding="utf-8", newline="\n")

    manifest = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "name": name,
        "version": crate["version"],
        "profile": profile,
        "target": TARGET,
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
    found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
                           check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
    if not found:
        raise Refusal("vswhere names no Visual Studio installation")
    return pathlib.Path(found)


def compile_program(vs: pathlib.Path, package: pathlib.Path, where: str, src: pathlib.Path,
                    work: pathlib.Path) -> pathlib.Path | None:
    exe = work / f"{where}-{src.stem}.exe"
    bat = work / f"build-{where}-{src.stem}.bat"
    bat.write_text(
        "@echo off\r\n"
        f'call "{vs}\\VC\\Auxiliary\\Build\\vcvars64.bat" > nul\r\n'
        f'cd /d "{work}"\r\n'
        f'cl /nologo /std:c11 /DZENOH_WINDOWS /I"{package / "include"}" "{src}" '
        f'"{package / where / "lib" / (LIBRARY + ".lib")}" /Fe:"{exe}"\r\n',
        encoding="ascii")
    proc = subprocess.run(["cmd.exe", "/c", str(bat)])
    return exe if proc.returncode == 0 and exe.is_file() else None


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
        statement = json.loads((package / STATEMENT).read_text(encoding="utf-8"))
        programs = sorted(p for p in (package / "examples").glob("*.c"))
        if not programs:
            raise Refusal("the package carries no example")
        failed = 0
        for where, _ in BUILDS:
            work = pathlib.Path(tmp) / f"work-{where}"
            work.mkdir()
            env = {**os.environ, "PATH": str(package / where / "bin") + os.pathsep + os.environ.get("PATH", "")}
            runs = [(src, []) for src in programs]
            runs.append((CHECK_PROGRAM, [statement["digest"], str(package / CATALOG_SAMPLE)]))
            for src, args in runs:
                exe = compile_program(vs, package, where, src, work)
                if exe is None:
                    verdict = "did not compile or link: FAIL"
                else:
                    try:
                        proc = subprocess.run([str(exe), *args], env=env, timeout=600)
                        verdict = "PASS" if proc.returncode == 0 else f"exit {proc.returncode}: FAIL"
                    except subprocess.TimeoutExpired:
                        verdict = "no answer within 600 s: FAIL"
                failed += not verdict.startswith("PASS")
                say(f"pico-package-test on Windows: {where} {src.name}: {verdict}")
        return 1 if failed else 0


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
    expect("the name carries version, profile, host and ten digits of the commit",
           package_name("0.1.0", "host-peer-ext", "0123456789abcdef") == "wz-capi-pico-0.1.0-host-peer-ext-windows-x64-0123456789")
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

        notices = render_notices("p", rows, [], {"release": "rustc 1.0.0", "dir": "licenses/rust-std-1.0.0",
                                                 "notice": "COPYRIGHT-library.html"},
                                 {"version": "1.0", "commit": "abc", "dir": "licenses/zenoh-pico"})
        expect("the notices list each linked package with the place of its texts",
               "| dual | 1.2.3 | MIT OR Apache-2.0 | crates.io | `licenses/dual-1.2.3/LICENSE-APACHE`, "
               "`licenses/dual-1.2.3/LICENSE-MIT` |" in notices)
        expect("a package with no text is listed under its own heading",
               "## Linked packages that ship no licence text (1)" in notices and "- bare 3.0.0: MIT" in notices)
        expect("the same rows give the same notices",
               notices == render_notices("p", rows, [], {"release": "rustc 1.0.0", "dir": "licenses/rust-std-1.0.0",
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
        "profile": "host-peer-ext", "features": ["std", "a"], "statement": statement})
    expect("the release notes keep the written part first", notes.startswith("# Notes\n\nwritten\n\n## This build"))
    expect("the release notes name the capabilities the build has and no other", "Capabilities (1): `a`" in notes)
    expect("the release notes name what is off its default, and only that",
           "L = 4 (default 2)" in notes and "M = 1" not in notes and "p = on (upstream off)" in notes)
    expect("a tree with changes says so", "with changes not committed" in notes)

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
        if len(argv) == 5 and argv[1] == "--build" and argv[3] == "--profile":
            out = pathlib.Path(argv[2]).resolve()
            out.mkdir(parents=True, exist_ok=True)
            build(out, argv[4])
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
    except Refusal as err:
        print(f"  pico-package REFUSED: {err}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

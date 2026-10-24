#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""The entry of `docs/target-build-contract.md`: build for a platform, describe what was built.

    wz_package.py --platform ID --artifact ID... --out DIR [--cargo-profile release|debug]
    wz_package.py --verify DIR
    wz_package.py --selftest

`package` (the default) builds the named artifacts for the platform with cargo, copies each into
`DIR/lib` or `DIR/bin`, measures every file from its own bytes (`elf_facts`) and writes
`DIR/wz-target-manifest.json`: the one file a deployment tool reads. `--verify` is the gate on it:
it re-measures every artifact the manifest names and compares, so a manifest that no longer says
what the files are is a finding.

## What it refuses, and why that is an exit and not a warning (T10)

A refusal writes NO manifest and removes the directory it made: a tool that reads a half-described
artifact would ship it. It refuses a platform it has no statement for (a platform that does not
state `os_provides` and `system_assumed` is unassessed), a missing toolchain variable (named, so
the caller sees which), a build whose capabilities ask for a facility the platform does not give
(naming the capability), a NEEDED nobody assumed and nothing bundles (naming the library), and a
stamp whose family is not the artifact's.

## What it does not do

The profile is not an input yet: it builds each artifact's default features. Resolving a registered
profile into an artifact's features waits for the mapping that says which profile builds which
artifacts. A native build (the platform's triple is the compiler's host) is built without
`--target`, so it shares the workspace's own build directory; a cross build passes it.

Exit 0 on success, 2 on a refusal, 1 on a failed `--verify` or a failure of the entry itself.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_facts  # noqa: E402
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST_NAME = "wz-target-manifest.json"
MANIFEST_SCHEMA = 1

TOP_KEYS = ["schema", "catalog_version", "built_from", "platform", "toolchain", "system_assumed", "artifacts"]
BUILT_FROM_KEYS = ["commit", "tree_clean"]
PLATFORM_KEYS = ["id", "triple", "os", "libc", "network_stack", "support", "strongest_green_lane"]
TOOLCHAIN_KEYS = ["rustc", "cc", "sdk"]
ARTIFACT_KEYS = ["id", "name", "kind", "path", "sha256", "size", "elf", "abi", "provides", "features",
                 "resolved_features", "device_requires", "unassessed_features"]
ELF_KEYS = ["class", "machine", "linking", "interpreter", "soname", "runpath", "rpath", "needed", "os_floor"]
FLOOR_KEYS = ["glibc", "android_api_note", "symbol_version_tags"]


class Refusal(Exception):
    """The entry will not describe this build."""


# ---------------------------------------------------------------------------
# What a built file is, from its bytes and the declaration
# ---------------------------------------------------------------------------


def classify_needed(needed: list[str], assumed: list[str], who: str) -> list[dict]:
    """Every NEEDED as `system` (assumed by the platform row) or a refusal naming the library."""
    out = []
    for soname in needed:
        if soname not in assumed:
            raise Refusal(f"{who} needs {soname}, which the platform does not assume and nothing bundles: "
                          "name it in the platform's system_assumed (measured on a device) or bundle it")
        out.append({"soname": soname, "provided_by": "system"})
    return out


def elf_object(measured: dict, assumed: list[str], who: str) -> dict:
    return {
        "class": measured["class"],
        "machine": measured["machine"],
        "linking": measured["linking"],
        "interpreter": measured["interpreter"],
        "soname": measured["soname"],
        "runpath": measured["runpath"],
        "rpath": measured["rpath"],
        "needed": classify_needed(measured["needed"], assumed, who),
        "os_floor": {
            "glibc": measured["glibc_floor"],
            "android_api_note": measured["android_api_note"],
            "symbol_version_tags": measured["symbol_version_tags"],
        },
    }


def provides_of(decl: dict, row: dict, features: list[str], measured: dict) -> list[dict]:
    """The roles a built artifact provides: a role whose feature is off is absent."""
    out = []
    for role in decl["roles"]:
        if role["artifact"] != row["id"]:
            continue
        need = role.get("needs_feature")
        if need is not None and need not in features:
            continue
        entry: dict = {"role": role["id"]}
        via = {}
        for key, name in (("via_argument", "argument"), ("via_kind", "kind"), ("via_key", "key")):
            if key in role:
                via[name] = role[key]
        if via:
            entry["via"] = via
        if "facts_list" in role:
            lists = measured["facts"]
            if lists is None or role["facts_list"] not in lists:
                raise Refusal(f"{row['id']} provides {role['id']} but its file has no facts list "
                              f"`{role['facts_list']}`: it was not built with the facts note")
            entry[role["facts_list"]] = lists[role["facts_list"]]
        out.append(entry)
    return out


def runtime_requires(decl: dict, platform: dict, row: dict,
                     resolved: dict[str, list[str]]) -> tuple[list[str] | None, list[str]]:
    """An executable's facilities from the runtime features cargo resolved for it.

    `None` is UNKNOWN (an enabled feature nobody assessed), with those features named beside it.
    A facility the platform lacks is a refusal naming the features that ask for it.
    """
    needs, unassessed = wz_config.resolve_runtime_needs(decl, resolved)
    provided = set(platform["os_provides"])
    rows = {(r["package"], r["feature"]): set(r["os_needs"]) for r in decl["runtime_features"]}
    for facility in sorted(set(decl["os_base"]) | {f for s in rows.values() for f in s}):
        if facility in provided:
            continue
        asking = [f"{p}/{f}" for (p, f), s in sorted(rows.items())
                  if facility in s and f in resolved.get(p, [])]
        if facility in decl["os_base"]:
            asking.insert(0, "base")
        if asking:
            raise Refusal(f"{row['id']} may ask for {facility}, which platform {platform['id']} does not "
                          f"provide (asked by {', '.join(asking)})")
    return needs, unassessed


def device_requires(decl: dict, platform: dict, row: dict, features: list[str]) -> list[str] | None:
    """The facilities a library's capabilities may ask for. A facility the platform lacks is a
    refusal naming the capability. (An executable's come from `runtime_requires`.)"""
    on = {f for f in features if f in decl["caps"]}
    gaps = wz_config.platform_gaps(decl, platform["id"], on)
    if gaps:
        why = "; ".join(f"{facility} (asked by {', '.join(who)})" for facility, who in sorted(gaps.items()))
        raise Refusal(f"{row['id']} may ask for facilities platform {platform['id']} does not provide: {why}")
    return sorted(wz_config.os_needs_of(decl, on))


def artifact_entry(decl: dict, platform: dict, row: dict, relpath: str, blob: bytes, features: list[str],
                   resolved: dict[str, list[str]] | None = None) -> dict:
    """The manifest's entry for one built file, from its bytes: the same call serves `package`
    (which writes it) and `--verify` (which compares it).

    `resolved` is the features cargo enabled in each package of the build (a build fact, recorded
    in the manifest for the assessed packages only, so a re-measurement can recompute from it).
    """
    measured = elf_facts.describe(blob)
    stamp = measured["abi_stamp"]
    if stamp["family"] != row["family"]:
        raise Refusal(f"{row['id']}'s stamp says family {stamp['family']!r}, not {row['family']!r}")
    features = sorted(features)
    kept = {p: sorted(set((resolved or {}).get(p, []))) for p in wz_config.ASSESSED_PACKAGES}
    if row["kind"] == "executable":
        requires, unassessed = runtime_requires(decl, platform, row, kept)
    else:
        requires, unassessed = device_requires(decl, platform, row, features), []
    return {
        "id": row["id"],
        "name": pathlib.PurePosixPath(relpath).name,
        "kind": row["kind"],
        "path": relpath,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "elf": elf_object(measured, platform["system_assumed"], row["id"]),
        "abi": {"family": stamp["family"], "revision": stamp["revision"], "layout": stamp["layout"]},
        "provides": provides_of(decl, row, features, measured),
        "features": features,
        "resolved_features": kept,
        "device_requires": requires,
        "unassessed_features": unassessed,
    }


def preflight(decl: dict, platform_id: str, artifact_ids: list[str]) -> tuple[dict, list[dict]]:
    """The platform and the artifact rows, or the refusal that stops the build before it starts."""
    platform = next((p for p in decl["platforms"] if p["id"] == platform_id), None)
    if platform is None:
        raise Refusal(f"no platform `{platform_id}` is declared "
                      f"(known: {', '.join(p['id'] for p in decl['platforms'])})")
    for key in ("os_provides", "system_assumed"):
        if key not in platform:
            raise Refusal(f"platform {platform_id} is unassessed: it states no `{key}`, and the entry does "
                          "not guess what a device has")
    rows = []
    for aid in artifact_ids:
        row = next((a for a in decl["artifacts"] if a["id"] == aid), None)
        if row is None:
            raise Refusal(f"no artifact `{aid}` is declared "
                          f"(known: {', '.join(a['id'] for a in decl['artifacts'])})")
        rows.append(row)
    # Declaration order, whatever order the caller named them in: the manifest is reproducible.
    order = {a["id"]: i for i, a in enumerate(decl["artifacts"])}
    return platform, sorted(rows, key=lambda r: order[r["id"]])


def assemble(decl: dict, platform: dict, built_from: dict, toolchain: dict, entries: list[dict]) -> dict:
    return {
        "schema": MANIFEST_SCHEMA,
        "catalog_version": decl["catalog_version"],
        "built_from": built_from,
        "platform": {
            "id": platform["id"],
            "triple": platform["triple"],
            "os": platform["os"],
            "libc": platform["libc"],
            "network_stack": platform.get("network_stack"),
            "support": platform["support"],
            "strongest_green_lane": platform["lane"],
        },
        "toolchain": toolchain,
        "system_assumed": list(platform["system_assumed"]),
        "artifacts": entries,
    }


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# The gate: re-measure what a manifest describes
# ---------------------------------------------------------------------------


def shape_findings(manifest: object) -> list[str]:
    """The manifest's shape: the keys of schema 1, in order, none more."""
    if not isinstance(manifest, dict):
        return ["the manifest is not a JSON object"]
    out: list[str] = []

    def keys(where: str, obj: object, want: list[str]) -> bool:
        if not isinstance(obj, dict):
            out.append(f"{where} is not an object")
            return False
        if list(obj) != want:
            out.append(f"{where} has the keys {list(obj)}, schema {MANIFEST_SCHEMA} has {want}, in that order")
            return False
        return True

    if not keys("the manifest", manifest, TOP_KEYS):
        return out
    keys("built_from", manifest["built_from"], BUILT_FROM_KEYS)
    keys("platform", manifest["platform"], PLATFORM_KEYS)
    keys("toolchain", manifest["toolchain"], TOOLCHAIN_KEYS)
    if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
        out.append("artifacts is not a non-empty list")
        return out
    for i, art in enumerate(manifest["artifacts"]):
        if keys(f"artifacts[{i}]", art, ARTIFACT_KEYS):
            if keys(f"artifacts[{i}].elf", art["elf"], ELF_KEYS):
                keys(f"artifacts[{i}].elf.os_floor", art["elf"]["os_floor"], FLOOR_KEYS)
    return out


def safe_relpath(path: str) -> bool:
    p = pathlib.PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and "\\" not in path


def verify_dir(out: pathlib.Path, decl: dict) -> list[str]:
    """What is wrong with a packaged directory, from its files and the declaration.

    Every measured field is read again from the file and compared with the manifest, so a file
    replaced after packaging, a manifest edited by hand and a declaration that moved are each a
    finding, and a file the manifest does not mention is one too.
    """
    path = out / MANIFEST_NAME
    if not path.is_file():
        return [f"{path} is missing"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return [f"{path} is not readable JSON: {err}"]
    out_findings = shape_findings(manifest)
    if out_findings:
        return out_findings
    findings: list[str] = []
    if manifest["schema"] != MANIFEST_SCHEMA:
        findings.append(f"schema is {manifest['schema']!r}, this gate reads {MANIFEST_SCHEMA}")
        return findings
    if manifest["catalog_version"] != decl["catalog_version"]:
        findings.append(f"catalog_version is {manifest['catalog_version']}, the declaration's is "
                        f"{decl['catalog_version']}")
    plat = manifest["platform"]
    row = next((p for p in decl["platforms"] if p["id"] == plat["id"]), None)
    if row is None:
        return findings + [f"the platform `{plat['id']}` is not declared"]
    want_platform = {"id": row["id"], "triple": row["triple"], "os": row["os"], "libc": row["libc"],
                     "network_stack": row.get("network_stack"), "support": row["support"],
                     "strongest_green_lane": row["lane"]}
    if plat != want_platform:
        findings.append(f"platform {plat} differs from its declaration {want_platform}")
    if "system_assumed" not in row or manifest["system_assumed"] != row["system_assumed"]:
        findings.append("system_assumed differs from the platform row's")
    if "os_provides" not in row or "system_assumed" not in row:
        return findings + [f"platform {row['id']} is unassessed in the declaration"]
    listed = set()
    for art in manifest["artifacts"]:
        who = f"artifact {art['id']!r}"
        arow = next((a for a in decl["artifacts"] if a["id"] == art["id"]), None)
        if arow is None:
            findings.append(f"{who} is not declared")
            continue
        if not safe_relpath(art["path"]):
            findings.append(f"{who}: path {art['path']!r} is not a relative path inside the directory")
            continue
        listed.add(art["path"])
        file = out / art["path"]
        if not file.is_file():
            findings.append(f"{who}: {art['path']} is missing")
            continue
        blob = file.read_bytes()
        try:
            again = artifact_entry(decl, row, arow, art["path"], blob, art["features"], art["resolved_features"])
        except (Refusal, elf_facts.ElfError) as err:
            findings.append(f"{who}: re-measuring {art['path']}: {err}")
            continue
        for key in ARTIFACT_KEYS:
            if again[key] != art[key]:
                findings.append(f"{who}: {key} is {art[key]!r} in the manifest and {again[key]!r} "
                                f"read from {art['path']} now")
    extra = sorted(str(p.relative_to(out)) for p in out.rglob("*")
                   if p.is_file() and p.name != MANIFEST_NAME and str(p.relative_to(out)) not in listed)
    for name in extra:
        findings.append(f"{name} is in the directory and the manifest does not describe it")
    return findings


# ---------------------------------------------------------------------------
# The entry
# ---------------------------------------------------------------------------


def run_text(argv: list[str], cwd: pathlib.Path | None = None) -> str | None:
    try:
        run = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=cwd)
    except OSError:
        return None
    return run.stdout if run.returncode == 0 else None


def rustc_identity() -> tuple[str, str]:
    """The compiler's own one line and its host triple, from `rustc -vV`."""
    text = run_text(["rustc", "-vV"])
    if text is None:
        raise RuntimeError("rustc -vV failed")
    fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
    return (f"rustc {fields['release']} ({fields['commit-hash'][:9]} {fields['commit-date']})", fields["host"])


def cc_identity(platform: dict, cross: bool) -> str | None:
    """The first line of the C compiler's `--version`. A cross build must name one it can run."""
    words = platform["triple"].replace("-", "_")
    command = os.environ.get(f"CC_{words}") or (None if cross else os.environ.get("CC") or "cc")
    if command is None:
        raise Refusal(f"CC_{words} is not set")
    text = run_text([*shlex.split(command), "--version"])
    if text is None:
        if cross:
            raise Refusal(f"CC_{words} ({command}) did not answer --version")
        return None
    return text.splitlines()[0] if text.strip() else None


def check_toolchain_env(platform: dict, cross: bool) -> None:
    if not cross:
        return
    missing = [name for name in wz_config.toolchain_env(platform) if not os.environ.get(name)]
    if missing:
        raise Refusal(f"platform {platform['id']} builds with variables the caller sets, and these are not: "
                      f"{', '.join(missing)}")


def git_state() -> dict:
    commit = (run_text(["git", "rev-parse", "HEAD"], ROOT) or "").strip()
    dirty = run_text(["git", "status", "--porcelain", "--untracked-files=no"], ROOT)
    return {"commit": commit or None, "tree_clean": dirty is not None and dirty.strip() == ""}


def package_name(package_id: str) -> str:
    """The package a cargo `package_id` names: `path+file:///x/crates/NAME#0.1.0`,
    `path+file:///x/DIR#NAME@0.1.0` and the older `NAME 0.1.0 (path+...)` forms."""
    if "#" in package_id:
        head, tail = package_id.split("#", 1)
        return tail.split("@", 1)[0] if "@" in tail else head.rstrip("/").rsplit("/", 1)[-1]
    return package_id.split(" ", 1)[0]


def cargo_build(platform: dict, cross: bool, row: dict, cargo_profile: str
                ) -> tuple[pathlib.Path, list[str], dict[str, list[str]]]:
    """Build one artifact; the file, the features cargo built it with, and the features it
    enabled in every package of the build (the union over that package's units)."""
    argv = ["cargo", "build", "-p", row["package"], "--message-format=json-render-diagnostics"]
    if cargo_profile == "release":
        argv.append("--release")
    if cross:
        argv += ["--target", platform["triple"]]
    run = subprocess.run(argv, cwd=ROOT / "crates", stdout=subprocess.PIPE, text=True, check=False)
    if run.returncode != 0:
        raise RuntimeError(f"cargo build -p {row['package']} failed ({run.returncode})")
    found = None
    resolved: dict[str, set[str]] = {}
    kind = "cdylib" if row["kind"] == "shared-library" else "bin"
    for line in run.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        pid = msg.get("package_id", "")
        resolved.setdefault(package_name(pid), set()).update(msg.get("features", []))
        if package_name(pid) != row["package"]:
            continue
        if kind not in msg["target"]["kind"]:
            continue
        files = [f for f in msg["filenames"] if f.endswith(".so")] if kind == "cdylib" else [msg.get("executable")]
        if files and files[0]:
            found = (pathlib.Path(files[0]), list(msg["features"]))
    if found is None:
        raise RuntimeError(f"cargo built nothing that is the {row['kind']} of {row['package']}")
    return found[0], found[1], {p: sorted(f) for p, f in resolved.items()}


def package(decl: dict, platform_id: str, artifact_ids: list[str], out: pathlib.Path, cargo_profile: str) -> int:
    platform, rows = preflight(decl, platform_id, artifact_ids)
    rustc, host = rustc_identity()
    cross = platform["triple"] != host
    check_toolchain_env(platform, cross)
    if out.exists() and any(out.iterdir()):
        raise Refusal(f"{out} exists and is not empty; the entry does not overwrite")
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    try:
        toolchain = {"rustc": rustc, "cc": cc_identity(platform, cross), "sdk": None}
        entries = []
        for row in rows:
            built, features, resolved = cargo_build(platform, cross, row, cargo_profile)
            want = f"lib{row['file']}.so" if row["kind"] == "shared-library" else row["file"]
            if built.name != want:
                raise RuntimeError(f"cargo built {built.name} for {row['id']}, the declaration says {want}")
            sub = "lib" if row["kind"] == "shared-library" else "bin"
            (out / sub).mkdir(exist_ok=True)
            shutil.copyfile(built, out / sub / want)
            blob = (out / sub / want).read_bytes()
            entries.append(artifact_entry(decl, platform, row, f"{sub}/{want}", blob, features, resolved))
        manifest = assemble(decl, platform, git_state(), toolchain, entries)
        (out / MANIFEST_NAME).write_text(render(manifest), encoding="utf-8")
        findings = verify_dir(out, decl)
        if findings:
            raise RuntimeError("the manifest just written does not verify: " + "; ".join(findings))
    except BaseException:
        # A refusal and a failure alike leave nothing a tool could read as a package.
        if created:
            shutil.rmtree(out)
        else:
            for leftover in out.iterdir():
                shutil.rmtree(leftover) if leftover.is_dir() else leftover.unlink()
        raise
    print(f"  wz-package: {platform['id']}: {len(entries)} artifact(s) in {out}, manifest verified")
    return 0


# ---------------------------------------------------------------------------
# Self-test: synthetic artifacts, so every refusal and finding has a file whose defect is known
# ---------------------------------------------------------------------------


def _stamp(family: str, revision: int = 1, layout: dict | None = None) -> bytes:
    return json.dumps({"schema": 1, "family": family, "revision": revision, "layout": layout or {}},
                      separators=(",", ":")).encode() + b"\x00"


def _facts(roles: list[str]) -> bytes:
    return json.dumps({"schema": 1, "lists": {"driver_roles": roles}}, separators=(",", ":")).encode() + b"\x00"


def _synthetic(row: dict, needed: list[str], roles: list[str] | None = None, family: str | None = None,
               revision: int = 1) -> bytes:
    notes = [(elf_facts.STAMP_SECTION, "wz", 1, _stamp(family or row["family"], revision))]
    if roles is not None:
        notes.append((elf_facts.FACTS_SECTION, "wz", 2, _facts(roles)))
    return elf_facts.build_test_elf(
        notes_=notes, needed=needed, machine=62,
        soname=f"lib{row['file']}.so" if row["kind"] == "shared-library" else None,
        interp="/lib64/ld-linux-x86-64.so.2" if row["kind"] == "executable" else None,
        verneed=[("libc.so.6", ["GLIBC_2.17", "GLIBC_2.34"])])


def _selftest() -> int:
    decl = wz_config.load_decl()

    def expect(label: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(f"selftest: {label}")

    def refuses(label: str, words: str, call) -> None:
        try:
            call()
        except Refusal as err:
            expect(f"{label} (the refusal does not say {words!r}: {err})", words in str(err))
            return
        raise AssertionError(f"selftest: {label}: nothing was refused")

    host = "linux-x86_64-glibc"
    assumed = next(p for p in decl["platforms"] if p["id"] == host)["system_assumed"]
    needs = [n for n in assumed if n != "ld-linux-x86-64.so.2"]
    platform, rows = preflight(decl, host, ["ap-demo", "capi-pico"])
    expect("artifacts come out in declaration order, not the caller's", [r["id"] for r in rows] == ["capi-pico", "ap-demo"])

    # The refusals before a build starts.
    refuses("an undeclared platform", "no platform", lambda: preflight(decl, "nowhere", ["capi-pico"]))
    refuses("an unassessed platform", "unassessed", lambda: preflight(decl, "android-arm64", ["capi-pico"]))
    refuses("an undeclared artifact", "no artifact", lambda: preflight(decl, host, ["nope"]))
    cross_platform = next(p for p in decl["platforms"] if p["id"] == "android-arm64")
    saved = {k: os.environ.pop(k) for k in wz_config.toolchain_env(cross_platform) if k in os.environ}
    try:
        refuses("a cross build with no toolchain variable", "CC_aarch64_linux_android",
                lambda: check_toolchain_env(cross_platform, True))
        check_toolchain_env(cross_platform, False)
    finally:
        os.environ.update(saved)

    # A clean package: assemble, write, verify.
    pico = next(a for a in decl["artifacts"] if a["id"] == "capi-pico")
    demo = next(a for a in decl["artifacts"] if a["id"] == "ap-demo")
    pico_blob = _synthetic(pico, needs)
    demo_blob = _synthetic(demo, needs, roles=["publish", "subscribe"])
    pico_features = ["peer", "scout", "link-udp", "multi-thread"]
    demo_features = ["zenoh-config", "other"]
    # What cargo enabled in the runtime for the default build: every feature the declaration assessed.
    demo_resolved = {"wz-runtime-tokio": sorted(r["feature"] for r in decl["runtime_features"])}
    with tempfile.TemporaryDirectory(prefix="wz-package-") as work:
        out = pathlib.Path(work) / "out"
        (out / "lib").mkdir(parents=True)
        (out / "bin").mkdir()
        (out / "lib" / "libwz_capi_pico.so").write_bytes(pico_blob)
        (out / "bin" / "wz-ap-demo").write_bytes(demo_blob)
        entries = [
            artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, pico_features),
            artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features, demo_resolved),
        ]
        manifest = assemble(decl, platform, {"commit": "0" * 40, "tree_clean": True},
                            {"rustc": "rustc 0", "cc": None, "sdk": None}, entries)
        expect("the shape of a manifest it wrote is clean", shape_findings(manifest) == [])
        manifest_path = out / MANIFEST_NAME
        manifest_path.write_text(render(manifest), encoding="utf-8")
        expect("the same inputs give the same bytes", render(manifest) == render(copy.deepcopy(manifest)))
        expect("a clean directory verifies", verify_dir(out, decl) == [])
        demo_entry = entries[1]
        expect("the session node is present when its feature is on",
               [p["role"] for p in demo_entry["provides"]] == ["session-node", "traffic-driver"])
        expect("the driver roles are the facts note's, in the manifest",
               demo_entry["provides"][1]["driver_roles"] == ["publish", "subscribe"])
        expect("a library's device_requires is the union of what its capabilities may ask",
               entries[0]["device_requires"]
               == ["entropy", "interface-list", "multicast", "sockets-tcp", "sockets-udp", "threads"])
        expect("an executable's is the base and what its assessed runtime features may ask",
               demo_entry["device_requires"]
               == ["entropy", "interface-list", "multicast", "sockets-tcp", "sockets-udp", "threads"]
               and demo_entry["unassessed_features"] == [])
        unknown = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                 {"wz-runtime-tokio": [*demo_resolved["wz-runtime-tokio"], "transport-link-ws"]})
        expect("an enabled runtime feature nobody assessed makes it unknown and is named",
               unknown["device_requires"] is None
               and unknown["unassessed_features"] == ["wz-runtime-tokio/transport-link-ws"])
        bare = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features)
        expect("an executable with no resolved runtime features asks only for the base",
               bare["device_requires"] == sorted(decl["os_base"]))
        expect("the glibc floor is measured", entries[0]["elf"]["os_floor"]["glibc"] == "GLIBC_2.34")
        no_config = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, ["other"], demo_resolved)
        expect("the session node is absent when its feature is off",
               [p["role"] for p in no_config["provides"]] == ["traffic-driver"])

        def verified_after(label: str, damage, words: str) -> None:
            """Damage a copy of the clean directory, and the gate must say `words`."""
            copy_dir = pathlib.Path(work) / "copy"
            if copy_dir.exists():
                shutil.rmtree(copy_dir)
            shutil.copytree(out, copy_dir)
            damage(copy_dir)
            found = verify_dir(copy_dir, decl)
            expect(f"{label}: not reported ({found})", any(words in f for f in found))

        def flip(dir_: pathlib.Path) -> None:
            file = dir_ / "bin" / "wz-ap-demo"
            data = bytearray(file.read_bytes())
            data[-1] ^= 0xFF
            file.write_bytes(bytes(data))

        verified_after("a byte of an artifact changed", flip, "sha256")
        verified_after("an artifact replaced by one that needs another library",
                       lambda d: (d / "bin" / "wz-ap-demo").write_bytes(_synthetic(demo, [*needs, "libfoo.so.1"],
                                                                                    roles=["publish", "subscribe"])),
                       "libfoo.so.1")
        verified_after("an artifact of another family",
                       lambda d: (d / "bin" / "wz-ap-demo").write_bytes(
                           _synthetic(demo, needs, roles=["publish", "subscribe"], family="capi-c")),
                       "family")
        verified_after("an artifact removed", lambda d: (d / "bin" / "wz-ap-demo").unlink(), "is missing")
        verified_after("a file the manifest does not describe",
                       lambda d: (d / "lib" / "stray.so").write_bytes(b"x"), "does not describe")
        verified_after("a revision moved in the file only",
                       lambda d: (d / "lib" / "libwz_capi_pico.so").write_bytes(_synthetic(pico, needs, revision=9)),
                       "revision")

        def edit_manifest(dir_: pathlib.Path, fn) -> None:
            data = json.loads((dir_ / MANIFEST_NAME).read_text())
            fn(data)
            (dir_ / MANIFEST_NAME).write_text(json.dumps(data, indent=2) + "\n")

        verified_after("a hash edited by hand", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].__setitem__("sha256", "0" * 64)), "sha256")
        verified_after("a feature list edited so a role appears or goes", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][1].__setitem__("features", ["other"])), "provides")
        verified_after("a key added to the manifest", lambda d: edit_manifest(
            d, lambda m: m.__setitem__("extra", 1)), "keys")
        verified_after("a key missing from an artifact", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].pop("sha256")), "keys")
        verified_after("an unknown schema", lambda d: edit_manifest(d, lambda m: m.__setitem__("schema", 2)), "schema")
        verified_after("a platform edited away from its declaration", lambda d: edit_manifest(
            d, lambda m: m["platform"].__setitem__("triple", "aarch64-linux-android")), "differs from its declaration")
        verified_after("a path that leaves the directory", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].__setitem__("path", "../x")), "relative path")
        verified_after("the manifest removed", lambda d: (d / MANIFEST_NAME).unlink(), "is missing")
        verified_after("a manifest that is not JSON", lambda d: (d / MANIFEST_NAME).write_text("{"), "not readable")

    # The refusals while describing a build.
    refuses("a NEEDED nobody assumed", "libfoo.so.1",
            lambda: artifact_entry(decl, platform, demo, "bin/wz-ap-demo",
                                   _synthetic(demo, [*needs, "libfoo.so.1"], roles=["publish"]), demo_features))
    refuses("a stamp of another family", "family",
            lambda: artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so",
                                   _synthetic(pico, needs, family="capi-c"), pico_features))
    refuses("an executable built without its facts note", "facts note",
            lambda: artifact_entry(decl, platform, demo, "bin/wz-ap-demo", _synthetic(demo, needs), demo_features))
    lacking = copy.deepcopy(decl)
    for p in lacking["platforms"]:
        if p["id"] == host:
            p["os_provides"] = [f for f in p["os_provides"] if f != "multicast"]
    lack_platform = next(p for p in lacking["platforms"] if p["id"] == host)
    refuses("a capability asking for a facility the platform lacks", "multicast (asked by multicast-transport",
            lambda: artifact_entry(lacking, lack_platform, pico, "lib/libwz_capi_pico.so", pico_blob,
                                   ["multicast-transport"]))
    refuses("a runtime feature asking for a facility the platform lacks",
            "multicast, which platform linux-x86_64-glibc does not provide (asked by wz-runtime-tokio/scouting-active, "
            "wz-runtime-tokio/transport-multicast)",
            lambda: artifact_entry(lacking, lack_platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                   demo_resolved))
    no_iface = copy.deepcopy(decl)
    for p in no_iface["platforms"]:
        if p["id"] == host:
            p["os_provides"] = [f for f in p["os_provides"] if f != "interface-list"]
    refuses("a platform with no interface listing cannot take a host build at all", "(asked by base",
            lambda: artifact_entry(no_iface, next(p for p in no_iface["platforms"] if p["id"] == host), demo,
                                   "bin/wz-ap-demo", demo_blob, demo_features, demo_resolved))
    expect("the same build is accepted where the platform gives the facility",
           artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, ["multicast-transport"])
           ["device_requires"] is not None)

    # The declaration and the stamp gate agree on which families exist.
    import abi_stamp_gate

    expect("every declared family is pinned by the stamp gate and every pinned family is declared",
           {a["family"] for a in decl["artifacts"]} == set(abi_stamp_gate.EXPECTED))
    expect("a file name is derived from the declaration, not a path",
           all("/" not in a["file"] for a in decl["artifacts"]))
    print("wz-package: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        try:
            return _selftest()
        except AssertionError as err:
            print(f"wz-package: FAIL -- {err}", file=sys.stderr)
            return 1
    decl = wz_config.load_decl()
    if len(argv) == 2 and argv[0] == "--verify":
        findings = verify_dir(pathlib.Path(argv[1]), decl)
        for finding in findings:
            print(f"  wz-package FAIL: {finding}", file=sys.stderr)
        if not findings:
            print(f"  wz-package: {argv[1]} verifies")
        return 1 if findings else 0
    platform_id = out = None
    artifact_ids: list[str] = []
    cargo_profile = "release"
    it = iter(argv)
    for arg in it:
        if arg == "--platform":
            platform_id = next(it, None)
        elif arg == "--artifact":
            artifact_ids.append(next(it, ""))
        elif arg == "--out":
            out = next(it, None)
        elif arg == "--cargo-profile":
            cargo_profile = next(it, "")
        else:
            print(f"wz-package: unknown argument {arg}", file=sys.stderr)
            return 2
    if not platform_id or not artifact_ids or not out or cargo_profile not in ("release", "debug"):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    try:
        return package(decl, platform_id, artifact_ids, pathlib.Path(out), cargo_profile)
    except Refusal as err:
        print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
        return 2
    except (RuntimeError, elf_facts.ElfError) as err:
        print(f"wz-package: FAIL -- {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

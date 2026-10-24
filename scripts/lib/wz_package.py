#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3521 (no register item) -- the entry of `docs/target-build-contract.md`: build for a platform,
describe what was built.

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
import re
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

TOP_KEYS = ["schema", "catalog_version", "built_from", "platform", "profile", "toolchain", "system_assumed",
            "artifacts"]
PROFILE_KEYS = ["id", "base", "capabilities", "limits"]
PROFILES_DIR = ROOT / "configs" / "profiles"
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


# ---------------------------------------------------------------------------
# A registered profile as an input (docs/target-build-contract.md T13)
# ---------------------------------------------------------------------------


def resolve_profile(decl: dict, profile_id: str) -> dict:
    """What a registered profile (`configs/profiles/<id>.conf`) asks of a build: its base original,
    the capabilities that are on once the original's defaults and the profile are merged, and the
    limits it sets off their defaults. Resolved strictly by the pinned Kconfig interpreter (C9)."""
    if not wz_config.PLATFORM_ID_RE.match(profile_id):
        raise Refusal(f"`{profile_id}` is not the name of a registered profile")
    path = PROFILES_DIR / f"{profile_id}.conf"
    if not path.is_file():
        known = sorted(p.stem for p in PROFILES_DIR.glob("*.conf"))
        raise Refusal(f"no registered profile `{profile_id}` (known: {', '.join(known)}); the entry takes a "
                      "name, not a path, so a profile is a versioned contract and not a file anyone wrote")
    if wz_config.kconfiglib_module() is None:
        raise Refusal("a profile is resolved by the pinned Kconfig interpreter, which is not installed: "
                      "run scripts/provision-kconfiglib.sh")
    try:
        kconf = wz_config.resolve([path])
    except wz_config.PresetError as err:
        raise Refusal(f"profile {profile_id} does not resolve: {err}") from err
    limits = {}
    for line in wz_config.resolved_limit_env(decl, kconf):
        key, _, value = line.partition("=")
        limits[key] = int(value)
    return {
        "id": profile_id,
        "base": wz_config.preset_header(path.read_text(encoding="utf-8")).get("base"),
        "capabilities": sorted(wz_config.resolved_caps(decl, kconf)),
        "limits": dict(sorted(limits.items())),
    }


def profile_cargo_args(decl: dict, row: dict, view: dict) -> list[str]:
    """The cargo arguments a library artifact is built with under a profile: no default features
    and exactly the features the capability graph gives its ABI for the profile's capabilities."""
    if row["kind"] != "shared-library":
        raise Refusal(f"profile {view['id']} cannot apply to {row['id']}: a profile resolves to the "
                      "features of an ABI library, and an executable has no such mapping")
    return wz_config.cargo_args(decl, row["abi"], set(view["capabilities"])).split()


def profile_findings(decl: dict, view: dict, entries: list[dict]) -> list[str]:
    """What is wrong with the artifacts a profile built: a capability the profile turns on that a
    library lacks, or one it leaves off that the library has."""
    out = []
    on = set(view["capabilities"])
    for art in entries:
        row = next((a for a in decl["artifacts"] if a["id"] == art["id"]), None)
        if row is None or row["kind"] != "shared-library":
            out.append(f"artifact {art['id']!r}: a profile does not apply to it")
            continue
        abi = row["abi"]
        built = set(art["features"])
        want = set(wz_config.features_for(decl, abi, on))
        for feature in sorted(want - built):
            out.append(f"artifact {art['id']!r} lacks the feature `{feature}` profile {view['id']} asks for")
        closed = wz_config.closure(decl["caps"], on)
        for cid in sorted(c for c in built
                          if c in decl["caps"] and abi in decl["caps"][c]["abis"] and c not in closed):
            out.append(f"artifact {art['id']!r} has the capability `{cid}`, which profile {view['id']} leaves off")
    return out


def assemble(decl: dict, platform: dict, built_from: dict, toolchain: dict, entries: list[dict],
             profile: dict | None = None) -> dict:
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
        "profile": profile,
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
    if manifest["profile"] is not None:
        keys("profile", manifest["profile"], PROFILE_KEYS)
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
    """A manifest path is a relative, `/`-separated string that stays inside the directory. It is
    judged as text (a manifest's path is not a place on this machine's filesystem), so no walked
    root's position can change the answer."""
    return bool(path) and not path.startswith("/") and ".." not in path.split("/") and "\\" not in path


def verify_dir(out: pathlib.Path, decl: dict, resolver=None) -> list[str]:
    """What is wrong with a packaged directory, from its files and the declaration.

    Every measured field is read again from the file and compared with the manifest, so a file
    replaced after packaging, a manifest edited by hand and a declaration that moved are each a
    finding, and a file the manifest does not mention is one too.
    """
    resolver = resolver or resolve_profile
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
    sdk = manifest["toolchain"]["sdk"]
    if (sdk or {}).get("kind") != row.get("sdk_kind") and sdk is not None:
        findings.append(f"toolchain.sdk is a `{sdk.get('kind')}` and the platform row names "
                        f"`{row.get('sdk_kind')}`")
    sdk_keys = {"android-ndk": {"kind", "revision"}, "qnx-sdp": {"kind", "revision"},
                "yocto": {"kind", "revision", "target_arch", "target_os"}}
    if sdk is not None and set(sdk) != sdk_keys.get(sdk.get("kind"), set()):
        findings.append(f"toolchain.sdk has the keys {sorted(sdk)}, the entry writes "
                        f"{sorted(sdk_keys.get(sdk.get('kind'), set())) or 'a kind it knows'} for that kind")
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
    profile = manifest["profile"]
    if profile is not None:
        # A profile is a registered contract, so it is resolved again from its file: a manifest that
        # names a profile the tree no longer resolves the same way, or artifacts that no longer
        # hold what the profile turns on and off, are findings.
        try:
            want = resolver(decl, profile["id"])
        except Refusal as err:
            findings.append(f"profile {profile['id']!r}: {err}")
        else:
            if profile != want:
                findings.append(f"profile {profile} differs from what {profile['id']} resolves to now {want}")
            findings += profile_findings(decl, want, manifest["artifacts"])
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


def read_ndk_revision(cc: str) -> str | None:
    """The NDK release a compiler path belongs to: `Pkg.Revision` of the `source.properties` the
    first directory above it that has one. Only the value is returned, never the path."""
    first = shlex.split(cc)[0] if cc.strip() else ""
    here = pathlib.Path(first).resolve().parent if first else None
    while here is not None and here != here.parent:
        props = here / "source.properties"
        if props.is_file():
            for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "Pkg.Revision":
                    return value.strip()
            return None
        here = here.parent
    return None


def read_qnx_sdp_release(target: str) -> str | None:
    """The SDP release a `QNX_TARGET` belongs to: the one directory under the SDP's
    `.packages/metadata/com.qnx.qnx<NNN>` (the release package, not one of its parts), two levels
    above the target directory. None when there is not exactly one, so a tree that holds two
    releases is refused rather than guessed. Only the directory's name is returned, never a path."""
    if not target.strip():
        return None
    root = pathlib.Path(target).resolve().parent.parent
    metadata = root / ".packages" / "metadata"
    if not metadata.is_dir():
        return None
    releases = sorted(entry.name for package in metadata.iterdir()
                      if re.fullmatch(r"com\.qnx\.qnx\d+", package.name) and package.is_dir()
                      for entry in package.iterdir() if entry.is_dir())
    return releases[0] if len(releases) == 1 else None


def sdk_identity(platform: dict, cross: bool) -> dict | None:
    """What identifies the SDK a cross build used; None for a native build (T2).

    Only the kinds the entry can read are read: a platform that names another is refused, so the
    manifest never carries a guessed identity.
    """
    if not cross:
        return None
    kind = platform.get("sdk_kind")
    if kind is None:
        raise Refusal(f"platform {platform['id']} is a cross build and names no sdk_kind")
    if kind == "yocto":
        # The values the SDK's environment script exports, never a path (T2).
        values = {key: os.environ.get(var, "") for key, var in
                  (("revision", "OECORE_SDK_VERSION"), ("target_arch", "OECORE_TARGET_ARCH"),
                   ("target_os", "OECORE_TARGET_OS"))}
        missing = [var for key, var in (("revision", "OECORE_SDK_VERSION"), ("target_arch", "OECORE_TARGET_ARCH"),
                                        ("target_os", "OECORE_TARGET_OS")) if not values[key]]
        if missing:
            raise Refusal(f"platform {platform['id']} names a yocto SDK and {', '.join(missing)} is not set: "
                          "source the SDK's environment script (scripts/yocto-toolchain-env.sh does)")
        return {"kind": kind, **values}
    if kind == "qnx-sdp":
        release = read_qnx_sdp_release(os.environ.get("QNX_TARGET", ""))
        if release is None:
            raise Refusal(f"platform {platform['id']} names a qnx-sdp SDK and QNX_TARGET does not lead to exactly "
                          "one release under .packages/metadata: source the SDP's environment script "
                          "(scripts/qnx-toolchain-env.sh does)")
        return {"kind": kind, "revision": release}
    if kind != "android-ndk":
        raise Refusal(f"platform {platform['id']}: the entry cannot read a `{kind}` SDK")
    cc = os.environ.get(f"CC_{platform['triple'].replace('-', '_')}", "")
    revision = read_ndk_revision(cc)
    if revision is None:
        raise Refusal(f"CC_{platform['triple'].replace('-', '_')} is not inside an NDK "
                      "(no source.properties with a Pkg.Revision above it)")
    return {"kind": kind, "revision": revision}


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


def cargo_argv(platform: dict, cross: bool, row: dict, cargo_profile: str,
               extra_args: list[str] | None = None) -> list[str]:
    """The cargo command that builds one artifact. A platform whose `std` is `build-std` has no
    prebuilt standard library, so the command builds it (`-Z` needs a nightly cargo, which is the
    caller's to put first, as it is the caller's to provide the SDK)."""
    argv = ["cargo", "build", "-p", row["package"], "--message-format=json-render-diagnostics"]
    if cargo_profile == "release":
        argv.append("--release")
    if cross:
        argv += ["--target", platform["triple"]]
        if platform.get("std") == "build-std":
            argv += ["-Z", "build-std=std,panic_abort"]
    return argv + (extra_args or [])


def cargo_build(platform: dict, cross: bool, row: dict, cargo_profile: str,
                extra_args: list[str] | None = None, extra_env: dict[str, str] | None = None
                ) -> tuple[pathlib.Path, list[str], dict[str, list[str]]]:
    """Build one artifact; the file, the features cargo built it with, and the features it
    enabled in every package of the build (the union over that package's units).

    `extra_args` and `extra_env` are what a profile adds: the feature selection and the limits.
    """
    argv = cargo_argv(platform, cross, row, cargo_profile, extra_args)
    run = subprocess.run(argv, cwd=ROOT / "crates", stdout=subprocess.PIPE, text=True, check=False,
                         env={**os.environ, **(extra_env or {})})
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


def package(decl: dict, platform_id: str, artifact_ids: list[str], out: pathlib.Path, cargo_profile: str,
            profile_id: str | None = None) -> int:
    platform, rows = preflight(decl, platform_id, artifact_ids)
    view = None
    if profile_id is not None:
        # Resolved and applied-or-refused before anything is built or created.
        view = resolve_profile(decl, profile_id)
        for row in rows:
            profile_cargo_args(decl, row, view)
    rustc, host = rustc_identity()
    cross = platform["triple"] != host
    check_toolchain_env(platform, cross)
    if out.exists() and any(out.iterdir()):
        raise Refusal(f"{out} exists and is not empty; the entry does not overwrite")
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    try:
        toolchain = {"rustc": rustc, "cc": cc_identity(platform, cross), "sdk": sdk_identity(platform, cross)}
        entries = []
        for row in rows:
            built, features, resolved = cargo_build(
                platform, cross, row, cargo_profile,
                profile_cargo_args(decl, row, view) if view else None,
                {k: str(v) for k, v in view["limits"].items()} if view else None)
            want = f"lib{row['file']}.so" if row["kind"] == "shared-library" else row["file"]
            if built.name != want:
                raise RuntimeError(f"cargo built {built.name} for {row['id']}, the declaration says {want}")
            sub = "lib" if row["kind"] == "shared-library" else "bin"
            (out / sub).mkdir(exist_ok=True)
            shutil.copyfile(built, out / sub / want)
            blob = (out / sub / want).read_bytes()
            entries.append(artifact_entry(decl, platform, row, f"{sub}/{want}", blob, features, resolved))
        manifest = assemble(decl, platform, git_state(), toolchain, entries, view)
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
    unassessed_decl = copy.deepcopy(decl)
    for p in unassessed_decl["platforms"]:
        if p["id"] == "linux-aarch64-glibc":
            p.pop("os_provides", None)
    refuses("an unassessed platform", "unassessed",
            lambda: preflight(unassessed_decl, "linux-aarch64-glibc", ["capi-pico"]))
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

    # A registered profile as an input (T13).
    view = {"id": "p-query", "base": "zenoh-c", "capabilities": ["query"], "limits": {"WZ_LIMIT_X": 7}}
    pico_args = profile_cargo_args(decl, pico, view)
    expect("a profile gives a library no default features and the graph's features for it",
           pico_args[:2] == ["--no-default-features", "--features"] and "query" in pico_args[2].split(","))
    refuses("a profile on an executable", "an executable has no such mapping",
            lambda: profile_cargo_args(decl, demo, view))
    wanted = sorted(wz_config.features_for(decl, "pico", {"query"}))
    on_view = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, wanted)
    expect("a library built with what the profile asks has no profile finding",
           profile_findings(decl, view, [on_view]) == [])
    short = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob,
                           [f for f in wanted if f != "query"])
    expect("a library lacking a feature the profile asks for is a finding",
           any("lacks the feature `query`" in f for f in profile_findings(decl, view, [short])))
    extra = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, [*wanted, "peer"])
    expect("a library with a capability the profile leaves off is a finding",
           any("has the capability `peer`" in f for f in profile_findings(decl, view, [extra])))
    expect("a profile does not apply to an executable's entry",
           any("does not apply" in f for f in profile_findings(
               decl, view, [artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                           demo_resolved)])))
    with tempfile.TemporaryDirectory(prefix="wz-package-profile-") as work:
        pdir = pathlib.Path(work) / "out"
        (pdir / "lib").mkdir(parents=True)
        (pdir / "lib" / "libwz_capi_pico.so").write_bytes(pico_blob)
        pmanifest = assemble(decl, platform, {"commit": "0" * 40, "tree_clean": True},
                             {"rustc": "rustc 0", "cc": None, "sdk": None}, [on_view], view)
        expect("a manifest that names a profile has the profile's keys", shape_findings(pmanifest) == [])
        (pdir / MANIFEST_NAME).write_text(render(pmanifest), encoding="utf-8")
        same = lambda _d, _i: copy.deepcopy(view)  # noqa: E731
        expect("a directory built under a profile verifies against its resolution",
               verify_dir(pdir, decl, same) == [])
        moved = lambda _d, _i: {**view, "capabilities": ["query", "queryable"]}  # noqa: E731
        expect("a profile that now resolves differently is a finding",
               any("differs from what" in f for f in verify_dir(pdir, decl, moved)))

        def gone(_d, _i):
            raise Refusal("no registered profile")

        expect("a profile the tree no longer has is a finding",
               any("profile 'p-query'" in f for f in verify_dir(pdir, decl, gone)))
        data = json.loads((pdir / MANIFEST_NAME).read_text())
        data["profile"]["extra"] = 1
        (pdir / MANIFEST_NAME).write_text(json.dumps(data))
        expect("a profile with an extra key is a shape finding",
               any("profile has the keys" in f for f in verify_dir(pdir, decl, same)))
    if wz_config.kconfiglib_module() is not None:
        real = resolve_profile(decl, "host-client-tcp-query")
        expect("a registered profile resolves strictly to its capabilities",
               "query" in real["capabilities"] and "peer" not in real["capabilities"]
               and real["base"] == "zenoh-c" and real["id"] == "host-client-tcp-query")
        refuses("a profile named by a path", "not the name of a registered profile",
                lambda: resolve_profile(decl, "../configs/profiles/host-client-tcp-query"))
        refuses("a profile nobody registered", "no registered profile", lambda: resolve_profile(decl, "nope"))
        expect("a resolved profile builds the libraries it can",
               profile_cargo_args(decl, next(a for a in decl["artifacts"] if a["id"] == "capi-c"), real)[0]
               == "--no-default-features")
    else:
        print("wz-package selftest: the real-profile arms SKIP, kconfiglib is absent "
              "(scripts/provision-kconfiglib.sh)")

    # Which cross platforms a machine can package.
    env_android = {name: "x" for name in wz_config.toolchain_env(
        next(p for p in decl["platforms"] if p["id"] == "android-arm64"))}
    expect("a cross platform with its toolchain variables set is ready",
           ready_platforms(decl, "x86_64-unknown-linux-gnu", env_android) == ["android-arm64"])
    expect("a cross platform with one variable missing is not ready",
           ready_platforms(decl, "x86_64-unknown-linux-gnu",
                           {k: v for k, v in env_android.items() if k != "AR_aarch64_linux_android"}) == [])
    expect("nothing is ready with no variables", ready_platforms(decl, "x86_64-unknown-linux-gnu", {}) == [])
    expect("the host's own triple is never a cross platform",
           "linux-x86_64-glibc" not in ready_platforms(decl, "x86_64-unknown-linux-gnu", env_android))
    expect("an unassessed platform is never ready, whatever the environment",
           "linux-aarch64-glibc" not in ready_platforms(
               unassessed_decl, "x86_64-unknown-linux-gnu",
               {**env_android, "CC_aarch64_unknown_linux_gnu": "x", "AR_aarch64_unknown_linux_gnu": "x",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "x"}))
    expect("an assessed platform with its variables set is ready",
           "linux-aarch64-glibc" in ready_platforms(
               decl, "x86_64-unknown-linux-gnu",
               {"CC_aarch64_unknown_linux_gnu": "x", "AR_aarch64_unknown_linux_gnu": "x",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "x"}))

    # The SDK identity of a cross build (T2).
    with tempfile.TemporaryDirectory(prefix="wz-ndk-") as ndk:
        root = pathlib.Path(ndk)
        (root / "toolchains" / "llvm" / "bin").mkdir(parents=True)
        (root / "source.properties").write_text("Pkg.Desc = Android NDK\nPkg.Revision = 30.0.1-beta1\n")
        clang = root / "toolchains" / "llvm" / "bin" / "clang"
        clang.write_text("")
        expect("the NDK revision is read from the source.properties above the compiler",
               read_ndk_revision(f"{clang} --target=x") == "30.0.1-beta1")
        expect("a compiler outside any NDK has no revision", read_ndk_revision("/usr/bin/true") is None)
        (root / "source.properties").write_text("Pkg.Desc = Android NDK\n")
        expect("a source.properties with no revision gives none", read_ndk_revision(str(clang)) is None)
        (root / "source.properties").write_text("Pkg.Revision = 30.0.1-beta1\n")
        android = next(p for p in decl["platforms"] if p["id"] == "android-arm64")
        var = "CC_aarch64_linux_android"
        saved_cc = os.environ.get(var)
        os.environ[var] = str(clang)
        try:
            expect("an Android build records the NDK revision and kind only",
                   sdk_identity(android, True) == {"kind": "android-ndk", "revision": "30.0.1-beta1"})
            os.environ[var] = "/usr/bin/true"
            refuses("a compiler outside an NDK", "not inside an NDK", lambda: sdk_identity(android, True))
        finally:
            if saved_cc is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = saved_cc
    qnx_plat = next(p for p in decl["platforms"] if p["id"] == "qnx710-iosock-aarch64")
    demo_row = next(a for a in decl["artifacts"] if a["id"] == "ap-demo")
    expect("a platform with no prebuilt std is built with build-std",
           cargo_argv(qnx_plat, True, demo_row, "release")[-4:]
           == ["--target", qnx_plat["triple"], "-Z", "build-std=std,panic_abort"])
    expect("a platform with a prebuilt std is not",
           "-Z" not in cargo_argv(next(p for p in decl["platforms"] if p["id"] == "android-arm64"),
                                  True, demo_row, "release"))
    expect("a native build is not, whatever its std row says",
           "-Z" not in cargo_argv(qnx_plat, False, demo_row, "release"))
    expect("a native build has no SDK identity", sdk_identity(platform, False) is None)
    refuses("a cross platform that names no sdk kind", "names no sdk_kind",
            lambda: sdk_identity({"id": "x", "triple": "t-1"}, True))
    refuses("an sdk kind the entry cannot read", "cannot read a `gcc` SDK",
            lambda: sdk_identity({"id": "x", "triple": "t-1", "sdk_kind": "gcc"}, True))
    with tempfile.TemporaryDirectory(prefix="wz-qnx-") as qnx:
        sdp = pathlib.Path(qnx)
        (sdp / "target" / "qnx7").mkdir(parents=True)
        meta = sdp / ".packages" / "metadata"
        (meta / "com.qnx.qnx710" / "7.1.0.00472T202006132107S").mkdir(parents=True)
        (meta / "com.qnx.qnx710.target.net.iosock" / "1.0").mkdir(parents=True)
        target = str(sdp / "target" / "qnx7")
        expect("the SDP release is the one directory of the release package, not of a part",
               read_qnx_sdp_release(target) == "7.1.0.00472T202006132107S")
        (meta / "com.qnx.qnx710" / "7.1.1.0").mkdir()
        expect("two releases under one SDP give none", read_qnx_sdp_release(target) is None)
        expect("an empty QNX_TARGET gives none", read_qnx_sdp_release("") is None)
        expect("a target outside any SDP gives none", read_qnx_sdp_release("/usr") is None)
        (meta / "com.qnx.qnx710" / "7.1.1.0").rmdir()
        qnx_row = {"id": "x", "triple": "t-1", "sdk_kind": "qnx-sdp"}
        saved_t = os.environ.get("QNX_TARGET")
        os.environ["QNX_TARGET"] = target
        try:
            expect("a QNX build records the SDP release and kind only",
                   sdk_identity(qnx_row, True) == {"kind": "qnx-sdp", "revision": "7.1.0.00472T202006132107S"})
            os.environ["QNX_TARGET"] = "/usr"
            refuses("a QNX build whose target leads to no release", "exactly one release",
                    lambda: sdk_identity(qnx_row, True))
        finally:
            if saved_t is None:
                os.environ.pop("QNX_TARGET", None)
            else:
                os.environ["QNX_TARGET"] = saved_t
    yocto_vars = ("OECORE_SDK_VERSION", "OECORE_TARGET_ARCH", "OECORE_TARGET_OS")
    saved_y = {v: os.environ.pop(v) for v in yocto_vars if v in os.environ}
    try:
        refuses("a yocto build with the SDK's variables unset", "OECORE_SDK_VERSION, OECORE_TARGET_ARCH, "
                "OECORE_TARGET_OS is not set", lambda: sdk_identity({"id": "x", "triple": "t-1",
                                                                     "sdk_kind": "yocto"}, True))
        os.environ.update({"OECORE_SDK_VERSION": "4.0.35", "OECORE_TARGET_ARCH": "aarch64",
                           "OECORE_TARGET_OS": "linux"})
        expect("a yocto build records the SDK's values and no path",
               sdk_identity({"id": "x", "triple": "t-1", "sdk_kind": "yocto"}, True)
               == {"kind": "yocto", "revision": "4.0.35", "target_arch": "aarch64", "target_os": "linux"})
    finally:
        for v in yocto_vars:
            os.environ.pop(v, None)
        os.environ.update(saved_y)

    # The declaration and the stamp gate agree on which families exist.
    import abi_stamp_gate

    expect("every declared family is pinned by the stamp gate and every pinned family is declared",
           {a["family"] for a in decl["artifacts"]} == set(abi_stamp_gate.EXPECTED))
    expect("a file name is derived from the declaration, not a path",
           all("/" not in a["file"] for a in decl["artifacts"]))
    print("wz-package: selftest OK")
    return 0


def ready_platforms(decl: dict, host: str, environ: dict[str, str]) -> list[str]:
    """The cross platforms this machine can package: assessed rows whose triple is not the
    compiler's host and whose toolchain variables are all set in `environ`.

    The lane runs exactly these, so a platform joins it by being declared and having its toolchain
    provided, not by an edit to the lane; an unset variable is "not provisioned here", which the
    lane reports and (when it is told the platform is required) fails.
    """
    out = []
    for p in decl["platforms"]:
        if "os_provides" not in p or "system_assumed" not in p or p["triple"] == host:
            continue
        if all(environ.get(name) for name in wz_config.toolchain_env(p)):
            out.append(p["id"])
    return out


def main(argv: list[str]) -> int:
    if argv in (["--ready"], ["--required-platforms"]):
        decl = wz_config.load_decl()
        host = rustc_identity()[1]
        if argv == ["--ready"]:
            print("\n".join(ready_platforms(decl, host, dict(os.environ))))
        else:
            print("\n".join(p["id"] for p in decl["platforms"]
                            if p["lane"] != "none" and "os_provides" in p and p["triple"] != host))
        return 0
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
    platform_id = out = profile_id = None
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
        elif arg == "--profile":
            profile_id = next(it, None)
        else:
            print(f"wz-package: unknown argument {arg}", file=sys.stderr)
            return 2
    if not platform_id or not artifact_ids or not out or cargo_profile not in ("release", "debug"):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    try:
        return package(decl, platform_id, artifact_ids, pathlib.Path(out), cargo_profile, profile_id)
    except Refusal as err:
        print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
        return 2
    except (RuntimeError, elf_facts.ElfError) as err:
        print(f"wz-package: FAIL -- {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

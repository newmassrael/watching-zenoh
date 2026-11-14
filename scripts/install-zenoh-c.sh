#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c.sh — provision the §5.27 `api-compat-c` ORACLE (R311y498).
#
# The zenoh-c oracle is THREE things, and Layer C1cc needs all of them:
#
#   1. the HEADERS (`zenoh.h` + friends) — cbindgen OUTPUT, so they ARE the ABI.
#      Upstream's own examples compile against these in both arms.
#   2. `libzenohc.so` — the REFERENCE arm. Compiling upstream's example against
#      wz shows it LINKS; running the same source against upstream's own
#      implementation is what shows wz's answers are the same answers.
#   3. the EXAMPLES — the corpus. A wz-authored C program calls what wz happens
#      to export, which is the bias that let the sibling atom sit at BUILT with
#      its headline claim unwitnessed. This round measured that bias: a
#      hand-picked 12-symbol list named four symbols zenoh-c never calls and
#      missed three it does.
#
# None of them is a wz dependency, so this script provisions them on demand,
# mirroring `build-zenohd.sh`'s role for the zenohd oracle.
#
# The version is PINNED, and the pin is the `ZENOH_C_VERSION` line of
# `scripts/zenoh-c-oracle.pin` -- read it there. R2256 found this sentence still
# saying 1.5.0 long after the constant moved, which is the failure mode a pin
# written twice always has: the reader believes the prose and the script obeys
# the constant.
# R2527 struck the restated number this sentence still carried: it said "1.10.0
# as this is written" one clause before telling the reader not to do that, and
# the bump to 1.10.1 would have made it wrong for the third time.
# The pin moved out of this script into that data file so that a host which
# cannot run this script (Windows has no bash) reads the same line instead of
# parsing a shell default. Do not restate the number here again; the assertion
# at the bottom reads it. A
# different zenoh-c is not a worse oracle, it is a DIFFERENT ABI — `zenoh_opaque.h`
# is generated per version and per `Z_FEATURE_*` set, and Layer C1cc's layout leg
# compares wz's footprints against whatever is installed. So the pin is asserted
# after install rather than assumed: an oracle that silently moved would turn a
# real drop-in into a red lane, or worse, a fake one into a green one.

set -euo pipefail

PIN_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/zenoh-c-oracle.pin"

# One key of the pin file. An absent or empty key FAILS: a pin read as empty
# would turn the fetch below into a request for no version at all.
pin_get() {
    local value
    value="$(sed -n "/^$1=/{s/^$1=//p;q;}" "$PIN_FILE")"
    if [[ -z "$value" ]]; then
        printf '[install-zenoh-c] FAIL: %s has no %s\n' "$PIN_FILE" "$1" >&2
        exit 1
    fi
    printf '%s' "$value"
}

ZENOH_C_VERSION="${ZENOH_C_VERSION:-$(pin_get ZENOH_C_VERSION)}"
PREFIX="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"
EXAMPLES_PARENT="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"

say() { printf '[install-zenoh-c] %s\n' "$*"; }

# ── inputs handed in, and what every archive is checked against ─────────────
#
# A host that fetches each release input once into its own content-addressed
# cache, and builds with no network, hands the installer what it fetched:
#
#   WZ_ZENOH_C_ARCHIVE  the release archive (zip) for this host's target
#   WZ_ZENOH_C_SOURCE   the source: the tag's tarball, or a directory holding
#                       the tree (a checkout or an unpacked tarball); the
#                       directory is copied, never written to
#
# Either one left unset is fetched from the pin's URL. Whichever way an archive
# arrives, it is checked against the pin's SHA-256 before anything is unpacked:
# a fetched archive and a handed-in one are the same claim, that these bytes are
# upstream's release, and the digest is what makes it one. A directory has no
# bytes to hash; it is held to the version it states, as a checkout always was.
#
# ── listing the inputs: --inputs ─────────────────────────────────────────────
#
# `install-zenoh-c.sh --inputs` downloads, installs and creates nothing. It
# prints what an install run on this host, at the pinned or overridden version,
# would fetch: one line per input, the release archive first and the source
# second, each three fields separated by one space:
#
#   <sha256> <url> <variable>     the input would be fetched from <url> and
#                                 held to <sha256>; `-` in place of the digest
#                                 when there is none to hold it to, which is a
#                                 version override without its digest variable
#                                 (WZ_ZENOH_C_SHA256, WZ_ZENOH_C_SOURCE_SHA256),
#                                 the case an install run refuses until one is
#                                 given
#   installed <path> <variable>   nothing would be fetched for that input: it
#                                 is already installed at <path> ($PREFIX for
#                                 the archive, the checkout for the source)
#
# <variable> is the one that hands the input in, WZ_ZENOH_C_ARCHIVE or
# WZ_ZENOH_C_SOURCE. The first and last fields never hold a space, so a path
# that does is everything between them. On success nothing else is printed on
# either stream and the exit is 0. What the caller has already handed in does
# not change the listing: it says what the installer needs, not what the caller
# holds. An arch upstream publishes no archive for, a pin key missing, and an
# installed checkout or header at another version fail the listing with the
# message and exit an install run gives for them, and no line is printed. The
# one refusal reported as a line instead is the override without a digest, as
# `-`: the caller that fetches the input is the one able to name its digest.
#
# The listing calls the same functions the install path does for every
# decision it reports, so the two cannot disagree about a target, a URL, a
# digest or what counts as installed.

# The digest an archive is held to, or nothing when there is none. The pin's
# digests belong to the pinned version, so a version override brings its own
# in the variable named by $2.
held_digest() {
    local given="${!2:-}"
    if [[ -n "$given" ]]; then
        printf '%s' "$given"
        return
    fi
    local pinned
    pinned="$(pin_get ZENOH_C_VERSION)" || exit 1
    if [[ "$ZENOH_C_VERSION" != "$pinned" ]]; then
        return
    fi
    pin_get "$1"
}

# The digest an archive must have: there is no path on which an archive is
# unpacked unchecked.
pinned_digest() {
    local digest
    digest="$(held_digest "$1" "$2")" || exit 1
    if [[ -z "$digest" ]]; then
        say "FAIL: zenoh-c $ZENOH_C_VERSION is an override and the pin's digests" >&2
        say "      are for $(pin_get ZENOH_C_VERSION); pass the archive's SHA-256 in $2." >&2
        exit 1
    fi
    printf '%s' "$digest"
}

# This host's Rust target triple, which names its release archive and the
# digest key the archive is held to. It sets `target` rather than printing it
# so that its FAIL reaches the stream an install run has always printed it on.
host_target() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) target="x86_64-unknown-linux-gnu" ;;
        aarch64) target="aarch64-unknown-linux-gnu" ;;
        *) say "FAIL: no published zenoh-c archive for arch $arch"; exit 1 ;;
    esac
}

# The release archive's URL for target $1.
release_url() {
    local archive url
    archive="$(pin_get ZENOH_C_ARCHIVE)" || exit 1
    archive="${archive//@VERSION@/$ZENOH_C_VERSION}"
    archive="${archive//@TARGET@/$1}"
    url="$(pin_get ZENOH_C_RELEASE_URL)" || exit 1
    url="${url//@VERSION@/$ZENOH_C_VERSION}"
    printf '%s' "${url//@ARCHIVE@/$archive}"
}

# The source archive's URL.
source_url() {
    local url
    url="$(pin_get ZENOH_C_SOURCE_URL)" || exit 1
    printf '%s' "${url//@VERSION@/$ZENOH_C_VERSION}"
}

# Whether the headers and the shared library are already at $PREFIX, in which
# case the release archive is neither fetched nor unpacked.
libs_installed() {
    [[ -f "$PREFIX/include/zenoh.h" && -f "$PREFIX/lib/libzenohc.so" ]]
}

# Whether a source tree is already at $EXAMPLES_PARENT, in which case the
# source is neither fetched nor copied; the version it states is checked by
# `check_source_version`, why in section 3.
source_installed() {
    [[ -f "$EXAMPLES_PARENT/examples/z_put.c" ]]
}

# The source tree at $EXAMPLES_PARENT states the version this run installs.
check_source_version() {
    local checkout_version
    checkout_version="$(tr -d '[:space:]' < "$EXAMPLES_PARENT/version.txt" 2>/dev/null || true)"
    if [[ "$checkout_version" != "$ZENOH_C_VERSION" ]]; then
        say "FAIL: the checkout at $EXAMPLES_PARENT is"
        say "      '${checkout_version:-unreadable}', not the pinned $ZENOH_C_VERSION."
        say "      It is the source every oracle ARM is built from and the tree"
        say "      the archive-arm derivation reads, so a stale one grades wz"
        say "      against an upstream this tree does not pin. Remove it and re-run,"
        say "      or, if it is a git checkout you keep, move it:"
        say "        git -C $EXAMPLES_PARENT fetch --depth 1 origin tag $ZENOH_C_VERSION"
        say "        git -C $EXAMPLES_PARENT checkout $ZENOH_C_VERSION"
        exit 1
    fi
}

# The header at $PREFIX states the version this run installs; why in the PIN
# assertion section.
check_installed_pin() {
    local installed
    installed="$(sed -n 's/^#define ZENOH_C "\(.*\)"$/\1/p' "$PREFIX/include/zenoh_configure.h" 2>/dev/null || true)"
    if [[ "$installed" != "$ZENOH_C_VERSION" ]]; then
        say "FAIL: installed zenoh-c is '${installed:-unknown}', expected $ZENOH_C_VERSION."
        say "      zenoh_opaque.h is generated per version, so a different oracle is a"
        say "      DIFFERENT ABI — Layer C1cc's layout leg compares against whatever is"
        say "      installed here. Remove $PREFIX/include/zenoh*.h and re-run."
        exit 1
    fi
}

# What `--inputs` prints. The checks run in the order an install run reaches
# them, and every one runs before the first line is printed, so a refusal
# prints no line.
list_inputs() {
    local target url digest archive_line source_line
    if libs_installed; then
        archive_line="installed $PREFIX WZ_ZENOH_C_ARCHIVE"
    else
        host_target
        url="$(release_url "$target")"
        digest="$(held_digest "ZENOH_C_SHA256_$target" WZ_ZENOH_C_SHA256)"
        archive_line="${digest:--} $url WZ_ZENOH_C_ARCHIVE"
    fi
    if source_installed; then
        check_source_version
        source_line="installed $EXAMPLES_PARENT WZ_ZENOH_C_SOURCE"
    else
        url="$(source_url)"
        digest="$(held_digest ZENOH_C_SOURCE_SHA256 WZ_ZENOH_C_SOURCE_SHA256)"
        source_line="${digest:--} $url WZ_ZENOH_C_SOURCE"
    fi
    if libs_installed; then
        check_installed_pin
    fi
    printf '%s\n' "$archive_line" "$source_line"
}

verify_sha256() {
    local got
    got="$(sha256sum "$1" | cut -d' ' -f1)"
    if [[ "$got" != "$2" ]]; then
        say "FAIL: $3 $1"
        say "      has SHA-256 $got,"
        say "      the pin says $2."
        exit 1
    fi
    say "$3 matches the pinned SHA-256"
}

# One archive, handed in or fetched, into $tmp/$2; prints its path.
obtain() {
    local given="$1" name="$2" url="$3" what="$4"
    if [[ -n "$given" ]]; then
        if [[ ! -f "$given" ]]; then
            say "FAIL: $what was handed in as $given, which is not a file" >&2
            exit 1
        fi
        say "reading $what handed in: $given" >&2
        printf '%s' "$given"
        return
    fi
    say "fetching $url" >&2
    # R2781 — retried, as every other release fetch here is; the mbedtls
    # installer's unretried twin lost hosted run 35614359072 to one 504.
    if ! curl -sSLf --retry 3 --retry-all-errors --retry-delay 2 \
        --connect-timeout 10 --max-time 180 -o "$tmp/$name" "$url"; then
        say "FAIL: could not fetch $what for zenoh-c ${ZENOH_C_VERSION}" >&2
        exit 1
    fi
    printf '%s' "$tmp/$name"
}

# ── what this run does ───────────────────────────────────────────────────────
#
# An argument the script does not take is refused rather than ignored: a typo
# of `--inputs` would otherwise start an install.
case "$#:${1:-}" in
    0:) ;;
    1:--inputs)
        list_inputs
        exit 0
        ;;
    *)
        say "FAIL: unknown arguments: $*" >&2
        say "      the one argument this takes is --inputs" >&2
        exit 2
        ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ── 1+2. headers and the shared library ──────────────────────────────────────
#
# From the upstream RELEASE archive rather than a source build: zenoh-c is a
# cbindgen wrapper over the zenoh Rust crate, so building it from source pulls
# the whole zenoh dependency graph for an artifact upstream already publishes.
# The archive is the same thing a zenoh-c user installs, which is the point — the
# oracle must be what a real consumer has, not something wz assembled.
if libs_installed; then
    say "headers + libzenohc.so already at $PREFIX"
else
    host_target
    url="$(release_url "$target")"
    digest="$(pinned_digest "ZENOH_C_SHA256_$target" WZ_ZENOH_C_SHA256)"
    zip="$(obtain "${WZ_ZENOH_C_ARCHIVE:-}" zenoh-c.zip "$url" "the release archive")"
    verify_sha256 "$zip" "$digest" "the release archive"
    unzip -q "$zip" -d "$tmp/unpacked"
    mkdir -p "$PREFIX/include" "$PREFIX/lib"
    # The archive's internal layout has moved between releases, so FIND the
    # artifacts rather than assuming a path — an assumed path that stops matching
    # fails as "oracle absent", which is a SKIP, which is green.
    inc_dir="$(dirname "$(find "$tmp/unpacked" -name zenoh.h -print -quit)")"
    lib_file="$(find "$tmp/unpacked" -name 'libzenohc.so*' -print -quit)"
    if [[ -z "$inc_dir" || -z "$lib_file" ]]; then
        say "FAIL: the archive contained no zenoh.h and/or libzenohc.so"
        exit 1
    fi
    cp -r "$inc_dir"/. "$PREFIX/include/"
    cp "$lib_file" "$PREFIX/lib/libzenohc.so"
    say "installed headers + libzenohc.so into $PREFIX"
fi

# ── 3. the example corpus ────────────────────────────────────────────────────
#
# R2535 — "already there" is not "at the pin", and the difference is what left
# this workstation grading five pushes against the wrong upstream. This tree is
# not merely the examples: it is the SOURCE CHECKOUT that
# `install-zenoh-c-arm.sh` copies to build every non-published oracle arm, and
# that `zenoh_c_archive_arm.py --derive` reads upstream's release workflow out
# of. The presence test below skipped it whenever the directory existed, so
# R2527's pin move to 1.10.1 re-fetched the ARCHIVE into $PREFIX — which the
# assertion at the bottom of this file checks — and silently kept a 1.10.0
# checkout here, which nothing checked. Hosted CI never saw it because its cache
# key carries the version, so a bump is a cache miss and a fresh tree.
#
# The repair is the same rule this file already applies one section down: read
# the version the artifact itself states and compare it to the pin. It FAILS on
# a mismatch instead of replacing the tree, for the same reason the assertion
# below does — this directory may be a checkout an operator moved on purpose,
# and `rm -rf` on it is not something a provisioning script should decide.
#
# An absent tree is made from the source archive rather than a git clone: the
# tag's tarball is the same tree (zenoh-c marks nothing export-ignore), and
# unlike a clone it is bytes the pin can hold to a digest, which a host that
# builds with no network can fetch once and hand in. Nothing downstream needs
# the history: the arm installer copies the tree without `.git`.
if source_installed; then
    say "checkout already at $EXAMPLES_PARENT"
else
    source_in="${WZ_ZENOH_C_SOURCE:-}"
    rm -rf "$EXAMPLES_PARENT"
    mkdir -p "$EXAMPLES_PARENT"
    if [[ -n "$source_in" && -d "$source_in" ]]; then
        say "copying the zenoh-c source tree handed in: $source_in"
        tar -C "$source_in" --exclude=target --exclude=build -cf - . \
            | tar -C "$EXAMPLES_PARENT" -xf -
        # A handed-in tree may be read-only; the copy is ours to build in and
        # to remove.
        chmod -R u+w "$EXAMPLES_PARENT"
    else
        src_url="$(source_url)"
        source_digest="$(pinned_digest ZENOH_C_SOURCE_SHA256 WZ_ZENOH_C_SOURCE_SHA256)"
        tarball="$(obtain "$source_in" zenoh-c-src.tar.gz "$src_url" "the source archive")"
        verify_sha256 "$tarball" "$source_digest" "the source archive"
        say "unpacking zenoh-c ${ZENOH_C_VERSION} source into $EXAMPLES_PARENT"
        tar -xzf "$tarball" -C "$EXAMPLES_PARENT" --strip-components=1
    fi
    if [[ ! -f "$EXAMPLES_PARENT/examples/z_put.c" ]]; then
        say "FAIL: the zenoh-c source holds no examples/z_put.c"
        exit 1
    fi
fi
check_source_version
say "source at $EXAMPLES_PARENT is zenoh-c $ZENOH_C_VERSION"

# ── the PIN assertion ────────────────────────────────────────────────────────
#
# Read from the installed header, not from what this script just did: on the
# already-present path above nothing was installed at all, and an oracle that
# drifted under a previous install is exactly what this catches.
check_installed_pin

# The Z_FEATURE set the archive was built with (the `unstable-shm` pair, derived
# by `scripts/lib/zenoh_c_archive_arm.py` rather than asserted here) decides
# `z_put_options_t`'s layout — its fields are
# `#if defined(Z_FEATURE_UNSTABLE_API)`-gated — and which examples compile at
# all. Printed so a hosted log records WHICH ABI the run validated —
# "wz is a zenoh-c drop-in" is not a complete sentence without it.
say "oracle ready: zenoh-c $ZENOH_C_VERSION at $PREFIX, examples at $EXAMPLES_PARENT/examples"
say "feature set:"
grep -E '^#define Z_FEATURE_' "$PREFIX/include/zenoh_configure.h" | sed 's/^/  /'

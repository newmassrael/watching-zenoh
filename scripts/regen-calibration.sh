#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# regen-calibration.sh -- regenerate crates/wz-capture/src/zenoh_calibration_generated.rs
# from the corpus in captures/corpus/ (docs/flow-zenoh-verdict.md section 6.8).
#
# The file holds the counts of the corpus and model 3's parameters computed from
# them (the regions, the priors, the null bounds), and
# nobody writes it by hand: after adding a capture to the corpus (a manifest entry
# and its line in a group), run this and commit the result with the capture. The
# test `the_generated_calibration_is_current` fails when the file is not what the
# corpus gives, and, with WZ_BLESS_CALIBRATION set, writes it, which is all this
# does. It is not a `bx` action: an action's output must lie outside what the
# `regen-codegen` action reads, which is every file (`**`), and the two would form
# a cycle. On a machine that should not build it, the failing test prints the file
# the corpus gives, and that text is the file.
#
# What it does not move: the example sums that the session table, the C header and
# the C consumer pin, and the design note's prose. A test names each when it no
# longer matches.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root/crates"

WZ_BLESS_CALIBRATION=1 cargo test -p wz-capture \
    --features dissect,reassembly,compression \
    the_generated_calibration_is_current

echo "regen-calibration: done. Review and commit crates/wz-capture/src/zenoh_calibration_generated.rs"

# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The number a ledger round takes, read from the store and nowhere else.
#
# R4392 (no register item) -- one read of the number a round takes.
#
# `scripts/file-round.sh` takes it on a queue candidate, the one place a round is
# filed; the read stays its own file so that any later reader of "the last round"
# reads the store the same way instead of a commit subject.

# The highest `Round N` the store holds, or nothing when the store lists none.
# `mnemosyne-cli` must be on PATH; the caller has already checked that it is.
wz_last_round() {
    mnemosyne-cli query --list-changelog \
        | sed -n 's/^Round \([0-9][0-9]*\)$/\1/p' \
        | sort -n | tail -n 1
}

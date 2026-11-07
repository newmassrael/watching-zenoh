# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The number a ledger round takes, read from the store and nowhere else.
#
# R4392 (no register item) -- one read of the number for land.sh and file-round.sh.
#
# Two callers take a number: `scripts/land.sh`, inside its push lock, and
# `scripts/file-round.sh`, on a queue candidate. They must read the same fact the same
# way, or a round filed by one could be numbered differently by the other, so the read
# is written once here and both source it.

# The highest `Round N` the store holds, or nothing when the store lists none.
# `mnemosyne-cli` must be on PATH; the caller has already checked that it is.
wz_last_round() {
    mnemosyne-cli query --list-changelog \
        | sed -n 's/^Round \([0-9][0-9]*\)$/\1/p' \
        | sort -n | tail -n 1
}

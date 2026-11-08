# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R4399 (no register item) -- what a ref of a push IS, so the pre-push hook can grade
# each kind by what it holds.
#
# The hook used to read one kind of push: a branch, with the last ref of the push as
# its range. A queue integrator (`bx --land`, bx RFC 0024) pushes more kinds, and a
# push of one atomic transaction carries several of them at once: the target branch,
# the queue's log, and the deletion of the item refs it has finished. Reading "the
# last ref" there grades the log's chain as though it were the branch. So every ref
# is classified first and each kind is graded by what it holds:
#
#   main         the branch that carries the ledger. Every gate of the hook.
#   queue-items  `<place>/items/<id>`: a commit a session submitted. It is PUBLIC, so
#                the public gates run on it (confidential vocabulary, home paths,
#                identities) and the repository's own gates do not: those judge the
#                candidate, after the integrator has put it on the tip.
#   queue-log    `<place>/log` and `<place>/lease`: the queue's own record, a chain
#                with no common ancestor with the branch. It is public too, so the
#                same public gates run on what the push adds to it, and nothing else.
#   other        any other ref (a branch): the hook's gates as before.
#
# `<place>` is `refs/bx-land/<branch>` or, on a remote that refuses that namespace,
# `refs/heads/bx-land/<branch>` (bx RFC 0024, 4.2). Both are read; a branch that
# happens to be named `bx-land/...` is the queue's by the same rule, which is the
# conservative reading: it gets the public gates and not the heavy ones.

# The kind of a remote ref name, on stdout: main | queue-items | queue-log | other.
wz_push_ref_kind() {
    case "$1" in
    refs/heads/main) echo main ;;
    refs/bx-land/*/items/* | refs/heads/bx-land/*/items/*) echo queue-items ;;
    refs/bx-land/*/log | refs/bx-land/*/lease | refs/heads/bx-land/*/log | refs/heads/bx-land/*/lease)
        echo queue-log
        ;;
    refs/bx-land/* | refs/heads/bx-land/*)
        # A name in the queue's namespace that is none of the three above is not one the
        # integrator writes. It is still not the branch: grade it as a record, whose
        # public gates are the strictest thing that can be said of a ref of unknown form.
        echo queue-log
        ;;
    *) echo other ;;
    esac
}

# The range of commits a push of a queue ref adds, on stdout; nothing (and rc 1) when it
# cannot be bounded.
#   $1 kind (queue-items | queue-log)   $2 the remote's value of the ref ("" or zeros: new)
#   $3 the pushed commit                $4 the zero id   $5 the branch's remote-tracking ref
wz_queue_push_range() {
    local kind="$1" remote="$2" tip="$3" zero="$4" trunk="$5"
    if [[ "$kind" == "queue-items" ]]; then
        # An item is a commit that descends from where its author branched: what it adds to
        # the remote is everything not already on the branch.
        if [[ -n "$trunk" ]]; then
            echo "$trunk..$tip"
            return 0
        fi
        return 1
    fi
    # The log and the lease are chains of their own: the new commits are the ones after the
    # value the remote holds, and a ref that is new is a chain that has just begun. A bare
    # `<tip>` is no range for the gates: `git diff <tip>` compares with the working tree, so
    # a chain with nothing in common with the branch would be graded against the checkout.
    # Both cases are therefore `<base>..<tip>`; a new chain (or one whose old value this
    # clone does not hold, which cannot be bounded by it) starts at the empty base.
    if [[ -n "$remote" && "$remote" != "$zero" ]] \
        && git cat-file -e "${remote}^{commit}" 2>/dev/null; then
        echo "$remote..$tip"
    else
        local base
        base="$(wz_empty_base)" || return 1
        echo "$base..$tip"
    fi
}

# The identity bx gives the queue's own commits, the log's and the lease's (bx
# `land/git.rs` IDENT). It is no person's address, so publishing it leaks nothing, and a
# commit the integrator puts on the branch keeps the clone's own identity instead, which
# the ordinary identity gate judges. Changing bx's constant means changing this one.
WZ_QUEUE_IDENT_EMAIL='bx-land@localhost'

# The identity gate for what a push adds to the queue's log: every author and committer is
# either an identity the repository accepts or the queue's own. Needs `ident-gate.sh`
# sourced. $1 the hook's label   $2 the `<base>..<tip>` range. rc 1 on a refusal.
wz_queue_log_identity_gate() {
    local hook="$1" range="$2" log sha author committer email bad=0
    if ! log="$(git log --format='%H %ae %ce' "$range" --)"; then
        echo "${hook}: \`git log ${range}\` failed; cannot determine which" >&2
        echo "  identities this push would publish." >&2
        return 1
    fi
    while read -r sha author committer; do
        [ -n "$sha" ] || continue
        for email in "$author" "$committer"; do
            if [ "$email" != "$WZ_QUEUE_IDENT_EMAIL" ] && ! wz_ident_allowed "$email"; then
                wz_ident_refuse "$hook" "this push would publish queue records by" "$email"
                bad=1
            fi
        done
    done <<<"$log"
    return "$bad"
}

# A parentless commit with the empty tree, on stdout: the base that makes "everything the
# chain holds" a `<base>..<tip>` range. Its id is fixed (identity and dates are pinned), so
# it is the same object on every machine; it is written to the object store and reachable
# from no ref, so `git gc` removes it.
wz_empty_base() {
    local tree
    tree="$(git hash-object -t tree -w --stdin </dev/null)" || return 1
    GIT_AUTHOR_NAME=wz GIT_AUTHOR_EMAIL=wz@localhost GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' \
        GIT_COMMITTER_NAME=wz GIT_COMMITTER_EMAIL=wz@localhost GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' \
        git commit-tree "$tree" -m 'empty base'
}

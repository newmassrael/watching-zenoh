# shellcheck shell=bash
# The PREVIOUS hosted run's verdict, read by a program instead of by a person.
#
# R311y765 (N70). This repository's operating rule is "push and continue;
# read the previous run at the START of the next round, and pay a red off as its
# own round". The rule is right — waiting on hosted CI cost whole rounds of
# wall-clock — but its enforcement was a human step, and R311y764 measured that
# step failing three times in a row: Layer A4 was red on `1808ba7f`, `8f19661e`
# and `6f689628`, three consecutive pushes, and no round attributed it.
#
# R311y764 closed the A4 case with a local gate (pre-push gate 2b). That fixes
# ONE lane. The half it does not reach is the whole reason the rule exists: the
# feature-subset matrix, Layers F / G / Q / Z / B2 and every other hosted-only
# lane are DELIBERATELY not mirrored locally (policy R311y386), so for them a
# human read is not merely the first detector — it is the only one.
#
# So this reads it. Not by waiting, which the owner ruled out explicitly, but at
# the next push: the moment the round-start read should already have happened.
#
# ## Why an acknowledgement rather than a refusal
#
# A gate that simply refused while the previous run is red would make the FIX
# unpushable, which is the one push that must always work. `WZ_ACK_RED=<run id>`
# is the escape, and its shape is the point: the id can only be supplied by
# someone who looked, it is specific to THAT run, and it cannot be left in the
# environment to cover the next red silently. The gate does the reading — it
# prints the failed jobs and steps — and then requires the reader to say so.
#
# ## What it does NOT do
#
# It never blocks on a run that is still going. `in_progress` / `queued` is
# reported and passed, because "do not wait for CI" is the standing rule this
# gate exists to make safe, not to reverse. The cost is stated rather than
# hidden: a red is caught at the NEXT push rather than at the one that caused
# it, exactly as the round-start read would have caught it.

# Read the hosted verdict for one commit.
#
# $1 — the commit sha whose run to grade (the tip being replaced).
# $2 — caller name, for the messages.
#
# Returns 0 to proceed, 1 to refuse. A verdict it cannot obtain is announced as
# NOT RUN and returns 0 — the same trade gate 0 already makes for an unbounded
# nda-scan range, and for the same reason: `gh` is not a declared prerequisite
# of a clone of this repository, and a network hiccup must not make pushing
# impossible. It must never print a green line for a check that did not happen.
wz_previous_run_gate() {
    local sha="$1"
    local context="$2"

    if [[ -z "$sha" ]]; then
        echo "$context: no previous commit to grade (new ref); hosted-verdict gate did NOT run." >&2
        return 0
    fi
    if ! command -v gh >/dev/null 2>&1; then
        echo "$context: \`gh\` is not on PATH — the hosted-verdict gate did NOT run." >&2
        echo "          A red in a hosted-only lane (matrix / F / G / Q / Z / B2) will" >&2
        echo "          reach origin unnoticed. Install gh, or read the run by hand." >&2
        return 0
    fi

    local runs
    if ! runs="$(gh run list --commit "$sha" --limit 20 \
        --json databaseId,status,conclusion,workflowName 2>/dev/null)"; then
        echo "$context: could not reach GitHub — the hosted-verdict gate did NOT run." >&2
        return 0
    fi
    if [[ -z "$runs" ]]; then
        echo "$context: gh returned nothing for ${sha:0:12}; the gate did NOT run." >&2
        return 0
    fi

    # THE CLASSIFICATION IS THE GATE, so it is written down once, here.
    #
    # `success` is the ONLY green. `cancelled` is the case this repository has
    # been burned by and the reason there are three buckets rather than two: it
    # is not a failure, and reading "not red" as "green" is how a run that never
    # graded anything passes for one that did.
    local verdict
    verdict="$(printf '%s' "$runs" | python3 -c '
import json, sys

try:
    runs = json.load(sys.stdin)
except ValueError:
    print("UNREADABLE\tgh returned something that is not JSON")
    raise SystemExit(0)

GREEN = {"success"}
RED = {"failure", "timed_out", "startup_failure"}

# AN EMPTY POPULATION IS NOT A PASS. gh run list answers an empty array for a
# commit hosted CI never saw, and the first draft of this fell through every
# bucket below and printed "was green" for it -- measured against a sha that
# does not exist. That is the most-repeated defect shape in this workspace,
# rebuilt inside the gate whose whole job is to catch it, so the count is
# checked before the loop. (No backticks and no apostrophes anywhere in this
# python: it is a single-quoted -c argument, so shellcheck reads a backtick as
# command substitution (SC2016) and an apostrophe as the closing quote
# (SC1011), and Layer 0 refuses both.)
if not runs:
    print("NORUN\tno hosted run exists for this commit")
    raise SystemExit(0)

pending, pending_ids, red, amber = [], [], [], []
for r in runs:
    name = r.get("workflowName") or "?"
    rid = r.get("databaseId")
    if r.get("status") != "completed":
        # The run-level word is carried for the message only. R2198 (item 545):
        # it covers a run whose jobs are finishing and one where not a job has
        # started with the SAME word, so the id travels with it and the KIND is
        # derived from the job list instead.
        pending.append("%s (%s) says %s" % (name, rid, r.get("status")))
        pending_ids.append(str(rid))
        continue
    c = r.get("conclusion")
    if c in GREEN:
        continue
    (red if c in RED else amber).append("%s\t%s\t%s" % (name, rid, c))

if red:
    print("RED\t" + "\t".join(red[:1]))
elif amber:
    # NOT a failure and NOT a pass. On main this workflow groups per commit and
    # does not cancel in progress (ci.yml:105-107), so a cancelled run here is
    # an anomaly rather than supersession, and it graded nothing either way.
    print("AMBER\t" + "\t".join(amber[:1]))
elif pending:
    print("PENDING\t" + ",".join(pending_ids) + "\t" + "; ".join(pending))
else:
    print("GREEN\t")
' 2>/dev/null)"

    if [[ -z "$verdict" ]]; then
        echo "$context: could not classify the hosted verdict; the gate did NOT run." >&2
        return 0
    fi

    local kind rest
    kind="${verdict%%$'\t'*}"
    rest="${verdict#*$'\t'}"

    case "$kind" in
        GREEN)
            echo "$context: previous hosted run for ${sha:0:12} was green."
            return 0
            ;;
        PENDING)
            # NOT a wait. The standing rule is push-and-continue; this line
            # exists so the next push is the one that grades it.
            #
            # R2198 (open-debt item 545) — but it no longer says "still
            # running" on the strength of the run-level word. MEASURED
            # 2026-08-30: run 33293532416 called itself `queued` while seven
            # of its twenty jobs had already FINISHED, and a run where not one
            # job has started carries that same word. One word, two states, and
            # this sentence used to render both the same way. The KIND below is
            # derived from `--json jobs` by scripts/lib/hosted_pending_kind.py,
            # which refuses to read the run-level word at all.
            local pending_ids pending_text first_id jobs_json pending_kind
            pending_ids="${rest%%$'\t'*}"
            pending_text="${rest#*$'\t'}"
            first_id="${pending_ids%%,*}"
            echo "$context: previous hosted run for ${sha:0:12} has not finished ($pending_text)."
            # The classifier's EXIT STATUS decides, not its output. A command
            # substitution discards the status, and this file is sourced into a
            # `set -e` hook: a bare assignment from a failing classifier would
            # both swallow the refusal and kill the push. So the status is
            # branched on, and an UNCLASSIFIED payload lands in the announce
            # arm below rather than being printed as though it were a kind.
            pending_kind=""
            if [[ -n "$first_id" ]] \
                && jobs_json="$(gh run view "$first_id" --json jobs 2>/dev/null)" \
                && [[ -n "$jobs_json" ]]; then
                if pending_kind="$(printf '%s' "$jobs_json" \
                    | python3 scripts/lib/hosted_pending_kind.py --check 2>/dev/null)"; then
                    :
                else
                    pending_kind=""
                fi
            fi
            if [[ -n "$pending_kind" ]]; then
                echo "          run ${first_id}: ${pending_kind}"
            else
                # A kind that could not be derived is announced, never guessed.
                echo "          run ${first_id}: the pending KIND could not be derived" >&2
                echo "          (no gh / no python3 / unreadable jobs payload); the" >&2
                echo "          run-level word above does NOT distinguish a run that is" >&2
                echo "          progressing from one where no job has started." >&2
            fi
            echo "          Not waiting — it will be graded at the next push."
            return 0
            ;;
        UNREADABLE|NORUN)
            # Announced, never green: this gate graded nothing about this
            # commit, and a line that reads like a pass is what the caller
            # would carry forward.
            echo "$context: $rest (${sha:0:12}) — the hosted-verdict gate did NOT run." >&2
            return 0
            ;;
    esac

    # RED or AMBER. Name the run, then show WHAT failed, so the acknowledgement
    # below is an informed one rather than a formality.
    local wf rid conclusion
    wf="$(printf '%s' "$rest" | cut -f1)"
    rid="$(printf '%s' "$rest" | cut -f2)"
    conclusion="$(printf '%s' "$rest" | cut -f3)"

    if [[ "${WZ_ACK_RED:-}" == "$rid" ]]; then
        echo "$context: previous run $rid is $conclusion — ACKNOWLEDGED via WZ_ACK_RED."
        echo "          Pay it off as its own round; this push proceeds."
        return 0
    fi

    echo "" >&2
    echo "$context: THE PREVIOUS PUSH'S HOSTED RUN IS NOT GREEN." >&2
    echo "          workflow=$wf  run=$rid  conclusion=$conclusion  commit=${sha:0:12}" >&2
    if [[ "$kind" == "AMBER" ]]; then
        echo "          \`$conclusion\` is not a failure and it is not a pass — that run" >&2
        echo "          graded nothing, and reading it as green is the mistake this" >&2
        echo "          bucket exists to prevent." >&2
    fi
    echo "" >&2
    gh run view "$rid" --json jobs 2>/dev/null | python3 -c '
import json, sys
try:
    jobs = json.load(sys.stdin).get("jobs", [])
except ValueError:
    raise SystemExit(0)
for j in jobs:
    if j.get("conclusion") in ("success", "skipped", None):
        continue
    print("          job:  %s [%s]" % (j.get("name"), j.get("conclusion")))
    for s in j.get("steps", []):
        if s.get("conclusion") not in ("success", "skipped", None):
            print("            step: %s [%s]" % (s.get("name"), s.get("conclusion")))
' >&2
    echo "" >&2
    echo "          This is carry N70: the hosted-only lanes have no local gate," >&2
    echo "          so an unread red survives until someone happens to look. Three" >&2
    echo "          consecutive rounds proved that a human read will not." >&2
    echo "" >&2
    echo "          Read it, then push again with:" >&2
    echo "            WZ_ACK_RED=$rid git push origin main" >&2
    echo "          (the id is per-run on purpose — it cannot cover the next red)." >&2
    return 1
}

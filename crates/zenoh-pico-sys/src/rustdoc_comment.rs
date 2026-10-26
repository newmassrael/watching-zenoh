// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// A C header comment made safe to read as rustdoc.
//
// bindgen copies the comment above a C declaration into the Rust binding as a doc
// comment, verbatim. zenoh-pico writes the layout of a wire message in its
// comments as an ASCII diagram, with an optional field as `~  [int_exts]   ~`,
// and one of them ends in a closing code fence that never opened. Rustdoc reads
// the first as an intra-doc link to an item that does not exist and the second as
// an empty code block, and both are errors of the documentation build, in a file
// no one writes (the generated bindings, under `OUT_DIR`) from a header this tree
// does not own (the pico submodule). So the build script rewrites the comment on
// the way through (`ParseCallbacks::process_comment`): a bracket outside a code
// fence is escaped, and a fence line that has no partner is dropped. Nothing is
// removed from the text a reader sees.
//
// A module of the crate as well as an `include!` of the build script, for the reason
// `cmake_cache` gives: a build script's logic is not compiled by `cargo test`, so a
// rule that lived only there could not be tested. Plain `//` comments throughout,
// because `include!` does not take inner doc comments.

/// `comment` as rustdoc reads it: brackets outside a code fence escaped, and a
/// code fence with no partner dropped.
pub fn rustdoc_safe(comment: &str) -> String {
    let lines: Vec<&str> = comment.split('\n').collect();
    let fences: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == "```")
        .map(|(at, _)| at)
        .collect();
    // An odd number of fence lines has one with no partner; the last is the one a
    // header leaves open (a closing fence written after text that never opened one).
    let unpartnered = if fences.len() % 2 == 1 {
        fences.last().copied()
    } else {
        None
    };
    let mut out = String::with_capacity(comment.len() + 8);
    let mut in_fence = false;
    let mut first = true;
    for (at, line) in lines.iter().enumerate() {
        if Some(at) == unpartnered {
            continue;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        if line.trim() == "```" {
            in_fence = !in_fence;
            out.push_str(line);
        } else if in_fence {
            out.push_str(line);
        } else {
            for c in line.chars() {
                if c == '[' || c == ']' {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod rustdoc_comment_tests {
    use super::rustdoc_safe;

    #[test]
    fn a_bracket_outside_a_fence_is_escaped() {
        assert_eq!(
            rustdoc_safe(" ~  [int_exts]   ~  if Z==1"),
            " ~  \\[int_exts\\]   ~  if Z==1"
        );
    }

    #[test]
    fn a_bracket_inside_a_fence_is_left_alone() {
        let text = "Layout:\n```\n[a] [b]\n```\nafter [c]";
        assert_eq!(
            rustdoc_safe(text),
            "Layout:\n```\n[a] [b]\n```\nafter \\[c\\]"
        );
    }

    #[test]
    fn a_fence_with_no_partner_is_dropped() {
        // The shape of the header comment: text, then a lone closing fence.
        let text = " Flags:\n - A: x\n ```";
        assert_eq!(rustdoc_safe(text), " Flags:\n - A: x");
    }

    #[test]
    fn a_partnered_pair_of_fences_is_kept() {
        let text = "a\n```\ncode\n```\nb";
        assert_eq!(rustdoc_safe(text), text);
    }

    #[test]
    fn a_comment_with_nothing_to_change_is_unchanged() {
        let text = " The length of the slice in bytes.\n Zero when empty.";
        assert_eq!(rustdoc_safe(text), text);
    }
}

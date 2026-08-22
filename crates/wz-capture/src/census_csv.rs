// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 2001 (item 473) — the census planes as ROWS, for the tool that reads
//! tables rather than documents.
//!
//! ## Why a third rendering, and why it is not a third opinion
//!
//! This crate already emits two documents from the same typed tables: the human
//! page ([`crate::report`]) and the JSON a consuming tool parses
//! ([`crate::census_json`]). Neither is a table. An aggregation plane — which
//! keyexpr carried what — is exactly the shape a spreadsheet or a `awk` reads,
//! and there was no way to get one out: the analyzer's `--json` is a nested
//! document whose rows a reader would have to re-derive.
//!
//! The danger a third rendering brings is a third opinion about WHAT A ROW IS,
//! which is open-debt item 253's family. It is avoided the only way it can be:
//! this module reads [`ThroughputTable`] and [`KeyexprRow`], the same types
//! `census_json` reads, and derives its columns from the same accessors. A row
//! here is a row there by construction, and the test that pins it compares the
//! two renderings of one table rather than comparing either to a transcript.
//!
//! ## What is NOT collapsed
//!
//! Both directions are kept, as columns rather than as extra rows. The type's
//! own doc says why the split exists — "the direction is the difference between
//! a publisher and a subscriber" — and a table that summed them would answer a
//! different question from the one the JSON answers. One line per keyexpr is
//! also what makes this a table a tool can pivot rather than a long form.
//!
//! ## RFC 4180, and the field that is EMPTY rather than zero
//!
//! `share_bp` is `None` when the capture has no sizeable payload at all, and
//! `census_json` emits `null` there because a zero would read as "this topic
//! carried nothing". CSV has no null, so the field is EMPTY — which every
//! reader distinguishes from `0` — and never `0`.

use alloc::format;
use alloc::string::String;

use crate::agg::{KeyexprCounts, KeyexprRow, ThroughputTable};

/// The column header this module's rows are under, in emit order.
///
/// Public because a consumer that writes its own header (splitting a capture
/// across files, say) must write THIS one, and because a test that pinned a
/// transcript of it here would be pinning the same string twice.
pub const KEYEXPR_COLUMNS: &str = "keyexpr,\
a_to_b_puts,a_to_b_dels,a_to_b_queries,a_to_b_replies,a_to_b_errs,\
a_to_b_payload_bytes,a_to_b_unsized_payloads,a_to_b_messages,\
b_to_a_puts,b_to_a_dels,b_to_a_queries,b_to_a_replies,b_to_a_errs,\
b_to_a_payload_bytes,b_to_a_unsized_payloads,b_to_a_messages,\
total_puts,total_dels,total_queries,total_replies,total_errs,\
total_payload_bytes,total_unsized_payloads,total_messages,\
share_bp,offset_space,first_anchor,last_anchor,anchors_exact";

/// The keyexpr throughput plane as CSV, header first.
///
/// Rows are in [`ThroughputTable::rows`] order — heaviest first — so the table
/// arrives sorted the way the page and the JSON present it and a reader who
/// takes the first N lines takes the same N.
pub fn keyexprs_csv(t: &ThroughputTable) -> String {
    let mut out = String::from(KEYEXPR_COLUMNS);
    out.push('\n');
    for row in t.rows() {
        push_row(row, t, &mut out);
    }
    out
}

fn push_row(row: &KeyexprRow, t: &ThroughputTable, out: &mut String) {
    push_field(&row.keyexpr, out);
    for counts in [&row.per_direction[0], &row.per_direction[1], &row.totals()] {
        push_counts(counts, out);
    }
    match t.share_bp(&row.keyexpr) {
        Some(bp) => out.push_str(&format!(",{bp}")),
        // EMPTY, not zero. See the module doc.
        None => out.push(','),
    }
    out.push_str(&format!(
        ",{},{},{},{}\n",
        row.anchors.name(),
        row.first_anchor,
        row.last_anchor,
        row.anchors_exact
    ));
}

fn push_counts(c: &KeyexprCounts, out: &mut String) {
    out.push_str(&format!(
        ",{},{},{},{},{},{},{},{}",
        c.puts,
        c.dels,
        c.queries,
        c.replies,
        c.errs,
        c.payload_bytes,
        c.unsized_payloads,
        c.messages(),
    ));
}

/// One field, quoted per RFC 4180 only when it has to be.
///
/// A keyexpr is not a controlled vocabulary here: this reader attributes rows
/// from whatever the wire carried, so a comma, a quote or a newline inside one
/// is a thing that CAN arrive and must not be able to move a column boundary.
/// Quoting unconditionally would also be correct and is not done, because a
/// file whose every field is quoted is harder for a person to read and this
/// rendering exists to be read by tools a person drives.
fn push_field(value: &str, out: &mut String) {
    let needs_quotes = value.contains([',', '"', '\n', '\r']);
    if !needs_quotes {
        out.push_str(value);
        return;
    }
    out.push('"');
    for ch in value.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header is EMITTED from the same constant a consumer reads, not
    /// transcribed beside it.
    ///
    /// ⚠ The invariant this module exists under -- that the CSV's rows are the
    /// JSON's rows, in the same order -- is pinned in `census_json`'s tests
    /// instead, beside the fixture that builds a real table. A second fixture
    /// here would be a second opinion about what a plane contains, which is the
    /// very thing this module's doc says it must not become.
    #[test]
    fn an_empty_table_is_a_header_and_nothing_else() {
        let csv = keyexprs_csv(&ThroughputTable::default());
        assert_eq!(
            csv,
            alloc::format!("{KEYEXPR_COLUMNS}\n"),
            "a capture with no attributed keyexpr still names its columns -- a \
             reader must be able to tell an empty table from a failed one"
        );
    }

    /// A field that could move a column boundary is quoted, and one that could
    /// not is left alone.
    ///
    /// Driven on the FUNCTION rather than through a fixture whose keyexprs
    /// happen to be tame: this reader takes keyexprs off the wire, so the
    /// hostile ones are exactly the case no capture in this repo produces.
    #[test]
    fn a_field_is_quoted_only_when_a_reader_would_otherwise_misread_it() {
        for (raw, expected) in [
            ("demo/a", "demo/a"),
            ("demo/**", "demo/**"),
            ("a,b", "\"a,b\""),
            ("say \"hi\"", "\"say \"\"hi\"\"\""),
            ("two\nlines", "\"two\nlines\""),
            ("cr\rhere", "\"cr\rhere\""),
        ] {
            let mut out = String::new();
            push_field(raw, &mut out);
            assert_eq!(out, expected, "field {raw:?}");
        }
    }
}

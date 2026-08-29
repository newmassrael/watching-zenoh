// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2100 (open-debt item 509) — every emitted document says its OWN revision,
//! and a key rename or removal cannot ship without moving it.
//!
//! # The hole this fills
//!
//! `wz_dissect.h` states the consumer contract in prose: read the returned
//! JSON *by name*, tolerate unknown keys, and `wz_dissect_abi_version` moves
//! "when a SYMBOL or the memory rule changes, never when the JSON gains
//! fields". Both halves of that are right, and together they left a break with
//! no way to be expressed. A key RENAMED or REMOVED is a real break for a
//! consumer reading by name — and the ABI revision is defined not to move for
//! it, while the document itself carried no revision of its own. Measured
//! 2026-08-24 for item 509: `schema_version` / `document_version` /
//! `doc_revision` / `"version"` appeared ZERO times in `census_json.rs` and
//! `fields_json.rs`.
//!
//! Item 288's landing (`the_census_documents_key_set_is_pinned`) closed the
//! AUTHOR-side half: a shape change now lands on a table inside the repository
//! where the author has to state it. What no signal reached was the CONSUMER,
//! which is a different mechanism and is what this module is.
//!
//! # Per DOCUMENT, not per library, and the basis is measured
//!
//! Item 509 left this round to decide it and named the test: does the consumer
//! read the documents as SEPARATE symbols? Read off `wz_dissect.h`, it does —
//! `wz_dissect_pcap_census`, `wz_dissect_pcap_fields`, `wz_dissect_pcap_summary`,
//! `wz_dissect_readable_surfaces`, `wz_dissect_selector_diagnose` and
//! `wz_dissect_declarations_diagnose` are six separate doors, and a consumer
//! calls the one it wants. A single library-wide number would tell a reader of
//! the census that the shape moved when what actually moved was the field
//! document it never calls, and the only safe response to a number that moved
//! is to re-check — so a coupled number costs exactly the audits it cannot
//! justify.
//!
//! # The dance a revision makes ordinary
//!
//! With a per-document revision, a rename stops being a break and becomes a
//! two-step edit anyone can execute:
//!
//! 1. append a revision that emits BOTH the old key and the new one, with the
//!    old one listed in [`crate::doc_revision::DocumentShape::retiring`];
//! 2. append the next revision, which drops it.
//!
//! Fully-qualified rather than bare, and that is not a style choice: this
//! module's doc is MERGED with the `pub mod` doc in `lib.rs`, so a bare
//! `[`audit`]` is resolved in the crate root where no such item exists — two
//! rustdoc errors on the first run of this file, and `wz-capture` carries a
//! doc-link budget of zero.
//!
//! [`crate::doc_revision::audit`] is what makes that the ONLY expressible path: a key that vanishes
//! between consecutive revisions without having been announced in the older
//! one is an error, so a silent removal cannot be written down at all.
//!
//! # What this module is NOT
//!
//! Not `capi_abi_pin.py`, and not item 240's table. Those pin the SYMBOL set
//! against the ABI revision. This pins the DOCUMENTS those symbols hand back,
//! one layer in — the distinction item 509 drew when it filed.
//!
//! `wz_dissect_transport_message` is deliberately OUT of scope, and that is a
//! decision rather than an omission: its document is a FIELD TREE whose keys
//! are the walkers' own field names, generated per protocol element, so there
//! is no fixed key set to pin and "the shape moved" is not a statement about
//! it. The walkers' naming contract is a different one and belongs with them.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// One document's shape AT one revision.
///
/// A ROW IN A HISTORY, not a description of today: the newest row for a
/// document is what it emits now, and the older rows are what make a removal
/// checkable. Dropping the history and keeping only the current shape would
/// leave the author free to rename a key by editing one line, which is the
/// state item 509 measured.
pub struct DocumentShape {
    /// The document's name, as it appears in its own `document.name`.
    pub document: &'static str,
    /// This shape's revision. Starts at 1 per document and rises by one.
    pub revision: u32,
    /// Every key the document emits at this revision, sorted and deduped.
    ///
    /// The WHOLE set and not the additions, for the reason
    /// `the_census_documents_key_set_is_pinned` gives: a rule that only
    /// refused removals would let the shape grow unremarked, and the growth is
    /// what a consumer pinned to a revision has to be told about.
    pub keys: &'static [&'static str],
    /// Keys ANNOUNCED here as going away in the next revision.
    ///
    /// The first half of the rename dance. Every entry must be in
    /// [`Self::keys`] — announcing the retirement of a key the document does
    /// not emit says nothing to anyone.
    pub retiring: &'static [&'static str],
    /// Every key whose VALUE this revision draws from a closed set, with that
    /// set written out.
    ///
    /// R2175 (open-debt item 552) — the axis [`Self::keys`] cannot see. See
    /// [`ValueFamily`].
    pub families: &'static [ValueFamily],
    /// Every TOP-LEVEL key of this document that is a PLANE at this revision —
    /// SORTED, and empty for a document that has none.
    ///
    /// # The hole this fills, and why neither of the axes above could
    ///
    /// R2180 (open-debt item 554). A plane that this build cannot FEED is
    /// emitted as `null` rather than as an empty table, on the rule
    /// `census_json`'s module doc states: an absent plane and an empty one are
    /// different answers about the capture. A consumer therefore has to tell
    /// "this key is a plane and this build has none of it" from "this key is
    /// simply not a plane" — and a `null` carries no keys, so there is nothing
    /// in it to tell them apart with.
    ///
    /// What a consumer had instead was a STRUCTURAL rule read off
    /// `census_json_where`'s doc: a plane carries `narrowed_by_selector`, so a
    /// top-level object holding that key is one. That rule is right for every
    /// plane this build can feed and says nothing at all about a `null`. The
    /// consumer that reported this filed it precisely: it was reading "a
    /// top-level `null` is an absent plane", which is TRUE of this library
    /// today and is not a contract anything promised.
    ///
    /// [`Self::keys`] cannot answer it — `exchanges` is in the key set whether
    /// it arrives as a table or as `null`, which is the point of pinning a
    /// SHAPE. [`Self::families`] cannot either: a plane's absence is not a word
    /// drawn from a vocabulary, it is the whole value going away.
    ///
    /// # Emitted, not merely recorded
    ///
    /// [`envelope_into`] writes this list into the document itself, so the
    /// answer travels WITH the census rather than beside it. The alternative
    /// considered was a second axis on `wz_dissect_readable_surfaces`, beside
    /// `value_families`, and it was rejected on one measured property: that
    /// door is a statement about the LIBRARY, and the census crosses the ABI as
    /// an owned heap string the caller may store, forward or compare against
    /// one it took earlier. A plane list fetched separately can therefore be
    /// paired with a document from a different build, and nothing in either
    /// would say so. In the envelope the list and the revision travel together.
    ///
    /// ⚠ What this does NOT rest on: R2180 checked whether `wz-analyze` writes
    /// this document and it does NOT — `--json` renders the CLI's own report
    /// (see `debt-census-emit-two-renderings`), and the census document reaches
    /// a consumer only through `wz-capi-dissect`. The argument above is about
    /// the owned string that door hands back, which is a fact of this ABI
    /// rather than of a second surface.
    ///
    /// # Why documents with no planes stay silent
    ///
    /// A document declaring `planes: []` would move its revision, and this
    /// module's own argument against a library-wide number applies: the only
    /// safe response to a number that moved is to re-check, so moving five
    /// revisions to say "nothing here" costs five audits that buy nothing.
    /// Silence is unambiguous because it is CHECKED —
    /// `every_top_level_null_is_a_declared_plane` refuses a top-level `null` in
    /// any document that has not declared it, so a document with no `planes`
    /// key is one a consumer has been shown can never hand it an undeclared
    /// `null`.
    pub planes: &'static [&'static str],
    /// For each family this revision declares, whether the WORD decides which
    /// keys arrive beside it — and, when it does, which keys each word brings.
    ///
    /// R2184 (open-debt item 556) — the THIRD axis of the document contract,
    /// and the one the two above are each blind to for a different reason.
    ///
    /// # The hole this fills
    ///
    /// [`Self::keys`] is a UNION over the whole document, so it cannot say
    /// "sometimes absent" at all: `value` is in the field document's key set
    /// whether the field object that would carry it opened or not.
    /// [`Self::families`] sees the WORD and stops there. So the sentence a
    /// consumer actually needs — *if `kind` is `opaque`, do not look for
    /// `value`* — was expressible in neither, and was therefore read off
    /// today's rendering. That is a parse contract nothing declared, which is
    /// the same shape item 554 had for planes and item 552 for vocabularies.
    ///
    /// # Why it hangs off the SHAPE and not off [`ValueFamily`]
    ///
    /// A field on `ValueFamily` would be mandatory on every row of every
    /// revision, including the eleven rows written before this axis existed,
    /// and the only way to fill those is to claim retroactively that revision 4
    /// declared something it did not. Here an older revision carries `&[]`,
    /// which is TRUE of it, and [`audit`] refuses the same emptiness on the
    /// NEWEST revision of a document that declares families — the rule that
    /// keeps this from becoming the unmeasured default R2181 had just finished
    /// closing on [`Self::planes`].
    ///
    /// # Sorted by key, and exhaustive where it applies
    ///
    /// At the newest revision every declared family appears exactly once, no
    /// more and no fewer: a family missing from this list is a key a consumer
    /// switches on with no answer about what comes with it, and an entry naming
    /// no family is a claim about something that cannot occur. Both are
    /// [`audit`] errors, in both directions.
    pub carries: &'static [KeyCarries],
}

/// What one family key's WORD decides about the object it sits in, at one
/// revision of one document.
///
/// R2184 (open-debt item 556). Paired with [`DocumentShape::carries`], which is
/// where the completeness rule lives.
pub struct KeyCarries {
    /// The family key this describes. Must be one [`DocumentShape::families`]
    /// declares at the same revision.
    pub key: &'static str,
    /// What the word decides.
    pub shape: CarriesShape,
}

/// The two answers a family key can give about the keys beside it.
///
/// R2184 (open-debt item 556). A CLOSED PAIR with no third state on purpose:
/// "not classified" must not be expressible, because an unclassified family is
/// exactly the silent default this axis exists to abolish. A revision that has
/// not yet made the judgement says so by having no [`KeyCarries`] row at all,
/// and [`audit`] permits that only where the revision is not the newest.
///
/// # How the two are told apart, and it is DERIVED rather than judged
///
/// `doc_revision::companions` reports one entry per OCCURRENCE. Group them by
/// word:
///
/// * every word mapped to exactly ONE companion set, and two or more distinct
///   sets among them — the word decides the shape, so [`Self::Discriminant`];
/// * any word seen with TWO different sets, or every word sharing one set —
///   something other than the word decides it, so [`Self::Passenger`].
///
/// MEASURED 2026-08-29 over the census and field documents: three of the eleven
/// families are discriminants and eight are passengers. The item that filed
/// this axis had measured two, from the two it happened to be looking at;
/// `fields.offset_space` is the third, and it is a discriminant for a reason no
/// `match` in the emitter shows — `packet` is written by the datagram row
/// emitter with a `packet` index beside it and `stream_byte` by the stream one
/// with `message_at` and `payload_decode`. A list would have missed it, which
/// is why the population is derived.
pub enum CarriesShape {
    /// The word does NOT decide which keys arrive beside it: this key is a
    /// passenger in a record whose shape something else fixes, and an
    /// inapplicable companion arrives as `null` rather than absent.
    Passenger,
    /// The word DECIDES it: each word arrives with its own companion keys,
    /// listed here for EVERY word the family declares, sorted by word.
    Discriminant(&'static [WordCarries]),
}

/// One word of a discriminant family, and every SHAPE its own object takes.
///
/// R2184 (open-debt item 556).
pub struct WordCarries {
    /// The word, as it appears in the document. Must be one of the family's
    /// [`ValueFamily::values`].
    pub word: &'static str,
    /// Every distinct key set this word's object is emitted with, BESIDE the
    /// family key itself — each sorted and deduped, the list of them sorted,
    /// and never empty.
    ///
    /// # A LIST of shapes, and not one shape, because a word does not always
    /// fix the whole object
    ///
    /// MEASURED 2026-08-29, and it refuted the single-shape form this axis was
    /// first written with: `fields[].offset_space == "stream_byte"` arrives in
    /// TWO shapes, with `payload_decode` and without, because that plane is
    /// present only when the caller supplied a format map. So the word decides
    /// `message_at` — `packet` never carries it — and does NOT decide
    /// `payload_decode`, and both facts are true of the same word at once.
    ///
    /// Declaring one set per word would have to choose between them: the
    /// INTERSECTION says nothing about `payload_decode` and reads as "never",
    /// which is the exact confusion [`DocumentShape::keys`] already causes and
    /// this axis exists to end; the UNION says `payload_decode` always comes,
    /// which is false. The set of shapes says both without a third state, and a
    /// third state is what an escape hatch is.
    ///
    /// A word's object with nothing else beside it is `&[&[]]` — one shape,
    /// empty — which is `fields[].kind == "opaque"`, the case this item was
    /// filed for. `&[]` is refused by [`audit`]: a word with NO shape is one
    /// nothing was measured about.
    ///
    /// The envelope keys of the enclosing object are included, because what a
    /// consumer parses is the object it is handed and not a diff against some
    /// other word's.
    pub shapes: &'static [&'static [&'static str]],
}

impl WordCarries {
    /// The keys present in EVERY shape of this word — what a consumer is
    /// guaranteed to find beside it.
    pub fn always(&self) -> Vec<&'static str> {
        let Some(first) = self.shapes.first() else {
            return Vec::new();
        };
        first
            .iter()
            .copied()
            .filter(|k| self.shapes.iter().all(|s| s.contains(k)))
            .collect()
    }

    /// The keys present in ANY shape of this word — what may arrive beside it.
    pub fn ever(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> =
            self.shapes.iter().flat_map(|s| s.iter().copied()).collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// `true` when some key's presence is DECIDED by the word — the property that
/// separates a discriminant from a passenger, computed the same way from a
/// declaration and from a derivation.
///
/// R2184 (open-debt item 556). There is a key one word always brings and
/// another never does: `fields[].kind` always brings `value` for `bits` and
/// never for `opaque`, and `fields[].offset_space` always brings `message_at`
/// for `stream_byte` and never for `packet`.
///
/// ⚠ ALWAYS on one side and EVER on the other, and the asymmetry is what keeps
/// a passenger from reading as a discriminant. MEASURED: `fields[].direction`
/// sees `message_at` with `a` in a stream row and not in a datagram one, so
/// `message_at` is in `ever(a)` and not in `always(a)` — a comparison between
/// two unions, or between two intersections, calls that a discriminant. It is
/// not: what decides the row is which emitter ran, and `direction` is a
/// passenger on it.
pub fn decides_a_key(rows: &[WordCarries]) -> bool {
    rows.iter().any(|w1| {
        let always = w1.always();
        rows.iter()
            .any(|w2| w2.word != w1.word && always.iter().any(|k| !w2.ever().contains(k)))
    })
}

/// One key whose value is drawn from a CLOSED SET this library owns, at one
/// revision of one document.
///
/// # The hole this fills, and why the key set could not
///
/// [`DocumentShape::keys`] pins the SHAPE. A consumer reading by name is safe
/// against an added key and is told about a removed one, and that is the whole
/// of what item 509 built. What it never covered is the consumer that reads a
/// key it already knows and SWITCHES ON THE STRING INSIDE IT.
///
/// Measured, and it is why this type exists: R2170 added `not_on_the_wire` as
/// an eighth `payload_decode.state`, and the header says in its own words that
/// it REPLACES what used to be reported as `no_payload`. Same key, same
/// revision, a different answer about the same record — and no number moved,
/// because no key had been renamed or removed. The contract was satisfied and a
/// consumer's `switch` fell through to its default.
///
/// # The ASYMMETRY, which is the opposite of the key set's
///
/// For KEYS the dangerous direction is REMOVAL: a name-reader breaks when a key
/// it reads stops arriving, while an added key it does not know is exactly what
/// "tolerate unknown keys" covers. So `keys` needs [`DocumentShape::retiring`],
/// a one-revision notice before a departure.
///
/// For VALUES it is the other way round. A value that DISAPPEARS leaves a
/// consumer's arm unvisited, which is a quiet result and not a wrong one. A
/// value that APPEARS falls through a `switch` that was exhaustive when it was
/// written — and a default arm reached by a value that has a meaning is how a
/// consumer reports "nothing to say" about a record the library described. So
/// there is no `retiring` here: the notice a new value needs is the REVISION
/// ITSELF, and the pin is what forces one.
///
/// # The residue, stated rather than hidden
///
/// A value whose MEANING narrows without the word changing is invisible to
/// this, and R2170 is that case too: `no_payload` still exists and still means
/// what it says — it simply stopped being said about SHM records. No
/// machine-readable form of "this word now covers less" is proposed here, and
/// pretending the vocabulary pin catches it would be the confident wrong
/// answer this workspace refuses harder than silence.
pub struct ValueFamily {
    /// The key the value sits under, as it appears in the document.
    ///
    /// A KEY and not a path, because that is what [`json_string_values`]
    /// reports and a second opinion about addressing would be a second
    /// walker. The consequence is stated where it bites: a key reused at two
    /// depths carries the UNION of both vocabularies, and
    /// `readable_surfaces.name` is the live example.
    pub key: &'static str,
    /// Every value the key can carry at this revision, sorted and deduped.
    ///
    /// WRITTEN OUT per revision rather than pointing at the live constant, and
    /// that is the whole mechanism: a table that read `PayloadDecode::STATES`
    /// would widen the moment the array did and the revision would never have
    /// to move. It is the same argument [`CENSUS_R3_KEYS`] makes about being
    /// spelled out rather than built from its predecessor — a pin that follows
    /// its subject is not a pin.
    pub values: &'static [&'static str],
}

/// Every document this library hands a consumer, at every revision it has had.
///
/// APPEND-ONLY IN SPIRIT AND CHECKED IN EFFECT. Nothing here forbids editing a
/// row in place, and nothing needs to: [`audit`] refuses a key that leaves
/// without having been announced in the PREVIOUS row, and an in-place edit
/// cannot retroactively put an announcement there. So the one edit that
/// matters — a rename — is the one that has to be spelled as two new rows.
///
/// Every document starts at revision 1 in the round that introduced the
/// number. That is not a claim that the shapes are new; it is the claim that
/// this is the first revision a consumer could ever read.
pub const DOCUMENT_HISTORY: &[DocumentShape] = &[
    DocumentShape {
        document: CENSUS,
        revision: 1,
        keys: CENSUS_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2119 (open-debt item 455) — the RENAME this table was built for, used
    // for the first time. `first_packet` reports a byte offset over a stream
    // link, so the name has been wrong for every reader of a TCP capture;
    // `first_anchor` is the name, and it joins the `AnchorSpace` vocabulary
    // rather than starting a second one.
    //
    // Both keys are emitted at this revision and the old one is ANNOUNCED
    // here. The next revision drops it, and `audit` is what makes that the
    // only writable path: a key that vanishes without an announcement in the
    // previous row is an error, so the break cannot be taken silently.
    DocumentShape {
        document: CENSUS,
        revision: 2,
        keys: CENSUS_R2_KEYS,
        retiring: &["first_packet"],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2123 (open-debt item 453) — revision 3 does two things and they are
    // separable on purpose.
    //
    // It DROPS `first_packet`, which revision 2 announced. That is the second
    // step of R2119's dance, taken on the schedule `retiring`'s own doc states
    // rather than deferred; nothing would have refused a revision that kept it
    // (open-debt item 534), which is exactly why it is done here rather than
    // left to whichever round noticed.
    //
    // And it ADDS `anchor_intervals` with its `first` / `last` / `records`,
    // so `anchors_exact: false` stops being the whole answer: the row now says
    // how far each contributing space reaches and how many of its records are
    // in each, instead of saying only that the pair covers part of it.
    DocumentShape {
        document: CENSUS,
        revision: 3,
        keys: CENSUS_R3_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2175 (open-debt item 552) — revision 4 changes NO KEY and declares five
    // VALUE FAMILIES, which is the first revision in this table to move for a
    // reason the key set cannot express. That is the point: `kind`, `mode`,
    // `offset_space`, `asker` and `declarer` are all keys a consumer switches
    // on, and until this row a word could join any of them in silence.
    //
    // An unchanged key set is not a new shape here — revision 2 was already an
    // alias of revision 1's — and `CENSUS_R4_KEYS` is spelled as that alias for
    // the same reason.
    DocumentShape {
        document: CENSUS,
        revision: 4,
        keys: CENSUS_R4_KEYS,
        retiring: &[],
        families: CENSUS_R4_FAMILIES,
        planes: &[],
        carries: &[],
    },
    // R2180 (open-debt item 554) — revision 5 ADDS `planes` and retires
    // nothing, and it is the first revision in this table to move for a
    // statement about the document's OWN keys rather than about a capture.
    //
    // Three of this document's five planes are emitted as `null` in a build
    // without the network codecs, and a `null` carries nothing a consumer can
    // read a plane's identity off. So `exchanges: null` was distinguishable
    // from a non-plane key only by knowing which keys are planes, which this
    // library had written down in prose and in three hand-copied test literals
    // — and the prose was already stale, saying "the two keys" over three of
    // them. See `DocumentShape::planes`.
    //
    // An ADDITION, so a consumer pinned to revision 4 loses nothing; what it
    // gains is the ability to read the plane set off the document it already
    // has, instead of off a rule that happens to hold today.
    DocumentShape {
        document: CENSUS,
        revision: 5,
        keys: CENSUS_R5_KEYS,
        retiring: &[],
        families: CENSUS_R5_FAMILIES,
        planes: CENSUS_R5_PLANES,
        carries: &[],
    },
    // R2184 (open-debt item 556) — revision 6 changes NO KEY, NO WORD and NO
    // PLANE, and declares which of the five families' words DECIDE the keys
    // that arrive beside them. The first revision in this table to move for the
    // third axis, the way revision 4 moved for the second.
    //
    // All five are PASSENGERS here, and that is a measured verdict rather than
    // an omission: this document's row emitters are straight-line, so an
    // inapplicable companion arrives as `null` and never as an absent key —
    // which is the rule `interests_json` states in its own comments six times
    // and which nothing had ever checked. `the_declared_carries_axis_is_the_one
    // _the_emitters_render` is what checks it, and a row emitter that started
    // choosing keys by a word fails there rather than reaching a consumer.
    DocumentShape {
        document: CENSUS,
        revision: 6,
        keys: CENSUS_R6_KEYS,
        retiring: &[],
        families: CENSUS_R6_FAMILIES,
        planes: CENSUS_R6_PLANES,
        carries: CENSUS_R6_CARRIES,
    },
    DocumentShape {
        document: FIELDS,
        revision: 1,
        keys: FIELDS_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2175 (open-debt item 552) — revision 2 does two things, and the second
    // is what the item is about.
    //
    // It ADDS the fifteen keys of the PAYLOAD PLANE. Revision 1 pinned the
    // document as emitted with `declarations: None`, so `payload_decode` and
    // everything under it — `state`, `descriptor_bytes`, `under`, `wrong` and
    // the rest — shipped to consumers covered by no revision at all. That is
    // how R2170 added `descriptor_bytes` to this document without any number
    // moving: not because the rule was skipped, but because the rule had never
    // reached the subtree.
    //
    // And it DECLARES the first three value families. Nothing retires: every
    // key here is new, which is the side of `wz_dissect.h`'s line a linking
    // consumer may ignore.
    DocumentShape {
        document: FIELDS,
        revision: 2,
        keys: FIELDS_R2_KEYS,
        retiring: &[],
        families: FIELDS_R2_FAMILIES,
        planes: &[],
        carries: &[],
    },
    // R2182 (open-debt item 555) — revision 3 changes NO KEY and declares the
    // family for `kind`, the discriminant of the FIELD TREE itself.
    //
    // The one key in this document a consumer switches on that revision 2 left
    // undeclared, and the consuming surface that reported it had lost a word to
    // exactly that: it read seven of the eight and never saw `opaque`, which is
    // the arm no capture in this tree produces. That is worth stating as the
    // reason a walk and not a capture is the population — MEASURED here, the
    // every-plane fixture reaches seven of these eight words, so a vocabulary
    // derived from an artifact alone would have shipped with the same hole the
    // consumer had.
    //
    // An ADDITION, so a consumer pinned to revision 2 loses nothing.
    DocumentShape {
        document: FIELDS,
        revision: 3,
        keys: FIELDS_R3_KEYS,
        retiring: &[],
        families: FIELDS_R3_FAMILIES,
        planes: &[],
        carries: &[],
    },
    // R2184 (open-debt item 556) — revision 4 changes no key and no word, and
    // declares the axis for all six of this document's families. THREE of the
    // eleven families in this table are discriminants and all three are here:
    // `kind`, `state` and `offset_space`.
    //
    // The third is the one no reading of the source would have offered.
    // `offset_space` is not a `match` anywhere — `packet` is written by
    // `push_datagram_flow` beside a `packet` index and `stream_byte` by
    // `push_stream_flow` beside `message_at` and `payload_decode` — so the word
    // decides the shape through two emitters rather than two arms. Item 556
    // filed with two discriminants measured; the derivation found three, which
    // is the whole reason it says to derive the population instead of listing
    // it.
    DocumentShape {
        document: FIELDS,
        revision: 4,
        keys: FIELDS_R4_KEYS,
        retiring: &[],
        families: FIELDS_R4_FAMILIES,
        planes: &[],
        carries: FIELDS_R4_CARRIES,
    },
    DocumentShape {
        document: SUMMARY,
        revision: 1,
        keys: SUMMARY_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2121 (open-debt item 460) — revision 2 ADDS `inert_counters` and
    // retires nothing. Two skip counters cannot move in this build whatever
    // the capture holds, and the document had no way to say so: a reader of
    // `"ipv4_fragment": 0` on a capture of nothing but fragments concluded
    // there were none.
    //
    // An ADDITION on purpose. Item 460 recorded that removing the two keys
    // needed a contract break, which was wrong — `audit` above makes a removal
    // an ordinary announce-then-drop — but the dance costs TWO revisions by
    // design, so a consumer pinned to the first has a window. Spending both in
    // one round would honour the machinery and defeat it. A key that only ever
    // ADDS needs no window at all.
    DocumentShape {
        document: SUMMARY,
        revision: 2,
        keys: SUMMARY_R2_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2122 (open-debt item 238) — revision 3 ADDS `undefined_mandatory_exts`
    // and `unaccounted_batch_bytes`, and retires nothing.
    //
    // Not a new measurement: the capture report has carried both since
    // R311y624 and this document had not, because the `framing` group was
    // written twice by hand. They arrive here because the two renderings now
    // come from ONE emitter, which is the repair `skips_json` already was and
    // the class R311y859 left open.
    DocumentShape {
        document: SUMMARY,
        revision: 3,
        keys: SUMMARY_R3_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    DocumentShape {
        document: READABLE_SURFACES,
        revision: 1,
        keys: READABLE_SURFACES_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2114 (open-debt item 237) — revision 2 ADDS `payload_field_types` and
    // retires nothing. A deployment that describes its own record has to know
    // which type spellings this build reads before it can write one, and the
    // alternative to asking the library is a list copied into a header that
    // ages the moment the table grows.
    DocumentShape {
        document: READABLE_SURFACES,
        revision: 2,
        keys: READABLE_SURFACES_R2_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2175 (open-debt item 552) — revision 3 ADDS `value_families` and its two
    // row keys, and retires nothing. An ADDITION, so a consumer pinned to
    // revision 2 loses nothing; what it gains is the ability to ASK which words
    // this build can put in each switchable key, instead of learning it when a
    // switch falls through.
    DocumentShape {
        document: READABLE_SURFACES,
        revision: 3,
        keys: READABLE_SURFACES_R3_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    // R2184 (open-debt item 556) — revision 4 ADDS three keys to the
    // `value_families` rows and retires nothing: `carries`, and the `word` /
    // `keys` of the rows under it.
    //
    // This is where the third axis reaches a consumer at RUNTIME. Revision 3
    // let a program ask which words a key can carry; this lets it ask which
    // keys each word arrives with, which is the question it had to answer by
    // reading a document and generalising. `carries` is `null` for a family
    // whose word decides nothing — a value and not an absence, this
    // document set's own rule — so "passenger" is something the door SAYS
    // rather than something a reader infers from a missing key.
    DocumentShape {
        document: READABLE_SURFACES,
        revision: 4,
        keys: READABLE_SURFACES_R4_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    DocumentShape {
        document: SELECTOR_DIAGNOSE,
        revision: 1,
        keys: SELECTOR_DIAGNOSE_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
    DocumentShape {
        document: DECLARATIONS_DIAGNOSE,
        revision: 1,
        keys: DECLARATIONS_DIAGNOSE_R1_KEYS,
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    },
];

// The key sets below are MEASURED, never transcribed: each was printed by the
// pin test that checks it, on the same fixture that test uses, and pasted back.
// That is item 400's prescription — a table filled from a different reading
// than the one that will be checked against it is a table nobody can reason
// about — and it is how `the_census_documents_key_set_is_pinned` and the C1bz
// budget are both maintained.

/// The census document (`wz_dissect_pcap_census` and its narrowed doors).
pub const CENSUS: &str = "census";
/// The field document (`wz_dissect_pcap_fields` and its bounded doors).
pub const FIELDS: &str = "fields";
/// The capture summary (`wz_dissect_pcap_summary`).
pub const SUMMARY: &str = "summary";
/// The readable-surfaces catalogue (`wz_dissect_readable_surfaces`).
pub const READABLE_SURFACES: &str = "readable_surfaces";
/// A selector's verdict (`wz_dissect_selector_diagnose`).
pub const SELECTOR_DIAGNOSE: &str = "selector_diagnose";
/// A declaration block's verdict (`wz_dissect_declarations_diagnose`).
pub const DECLARATIONS_DIAGNOSE: &str = "declarations_diagnose";

/// The census document's key set at revision 1.
///
/// MOVED here from `the_census_documents_key_set_is_pinned`, which R311y923
/// wrote as a literal inside the test. The test now reads this table, so there
/// is ONE place the census document's shape is written down and the revision
/// sits beside it — the whole point of the move: a key set pinned in one file
/// and a revision declared in another are two facts that can disagree.
pub const CENSUS_R1_KEYS: &[&str] = &[
    "a",
    "a_to_b",
    "addr",
    "admissible",
    "aggregate",
    "anchors_exact",
    "answers",
    "answers_in_scope",
    "asked_at",
    "asker",
    "asks",
    "at_most_bytes",
    "attributed_bytes",
    "b",
    "b_to_a",
    "by_kind",
    "bytes",
    "cancelled_at",
    // Round 2042 (open-debt item 359) — the CEILINGS in force, beside the
    // losses they were measured against. Five keys under one `caps` object, so
    // a reader of `dropped_by_limits` can tell an unbounded run from a bounded
    // one.
    "caps",
    "children",
    "closed_at",
    "completed",
    "completion",
    "consistent",
    "contradictions",
    "count",
    "declaration",
    "declarations",
    "declared",
    "declared_at",
    "declarer",
    // Round 2016 (item 268) — the zid that made a declaration, joined from the
    // node plane. ADDED and not renamed, so it falls on the side of
    // `wz_dissect.h`'s line a linking consumer may ignore.
    "declarer_zid",
    "dels",
    "descriptors",
    // R2100 (open-debt item 509) — the envelope's own three keys. They are the
    // reason a consumer can tell this revision from the next one, so they are
    // part of the pinned set like any other.
    "document",
    "dropped_by_limits",
    "elsewhere",
    "errs",
    "evidence",
    "exchanges",
    "first_anchor",
    // ITEM 455 LIVES HERE: over a stream link this number is a BYTE OFFSET and
    // the name says packet. Renaming it is now an ordinary two-revision edit
    // (emit both, announce the old one in `retiring`, drop it next revision)
    // rather than the unexpressible break item 509 measured.
    "first_packet",
    "first_reply",
    "flow",
    "flows",
    "frames",
    "frames_per_flow",
    "gaps",
    "halted_batches",
    "hello",
    "high",
    "id",
    "inadmissible",
    "init",
    "interests",
    "join",
    "judged",
    "keyexpr",
    "keyexprs",
    "keys",
    "kind",
    "last_anchor",
    "links",
    "liveliness_token",
    "locators",
    "low",
    "matched",
    "max_flows_per_table",
    "max_ms",
    "max_scout_askers",
    "mean_ms",
    "messages",
    "min_ms",
    "mismatched",
    "mode",
    "name",
    "narrowed_by_selector",
    "nodes",
    "non_monotonic",
    "not_as_declared",
    "offset_space",
    "orphan_answers",
    "orphan_responses",
    "orphan_withdrawals",
    "payload_bytes",
    "payload_bytes_ceiling",
    "payloads",
    "port",
    "prefix",
    "puts",
    "queries",
    "queryable",
    "queryables",
    "records",
    "rejected",
    "replies",
    "requests",
    "restricted",
    "revision",
    "rows",
    "scout",
    "scout_askers",
    "selection",
    "share_bp",
    "silent",
    "skipped",
    "skipped_packets",
    "solicited_by",
    "source_ahead_of_observer",
    "stream_bytes",
    "stream_bytes_per_direction",
    "subscriber",
    "subscribers",
    "subtrees",
    "tokens",
    "total_ms",
    "total_payload_bytes",
    "totals",
    "unanswered",
    "unattributed_bytes",
    "unattributed_records",
    "unattributed_requests",
    "unclaimed",
    "unclaimed_exact",
    "unclosed",
    "undecidable",
    "undecided",
    "undeclarations",
    "undecompressible_batches",
    "unjudged_answers",
    "unknown_ids",
    "unlocatable_records",
    "unmeasured_payloads",
    "unparsed_bytes",
    "unread",
    "unresolvable_fragments",
    "unresolved",
    "unresolved_declarations",
    "unresolved_records",
    "unsized_payloads",
    "unstamped",
    "walked_records",
    "whatami",
    "wire_bytes",
    "withdrawn_at",
    "zid",
];
/// R2119 (open-debt item 455) — the census document's key set at revision 2,
/// which is revision 1's set EXACTLY.
///
/// A revision that adds no key is the surprise here, and it is the honest
/// answer: `first_anchor` was already a key of this document — the throughput
/// plane has emitted it since R311y919 — so putting it on the node row spends
/// no new name. What revision 2 carries is the ANNOUNCEMENT: `first_packet` is
/// listed in that row's `retiring`, which is what lets the next revision drop
/// it at all.
///
/// Aliased rather than copied, and that is the whole point. A second
/// hand-written list of 146 names would be wrong on the day it was written —
/// measured, on the first draft of this very constant, which came out 71 names
/// long and disagreed with its predecessor in both directions.
pub const CENSUS_R2_KEYS: &[&str] = CENSUS_R1_KEYS;

/// The census document's key set at revision 3 (R2123, open-debt item 453).
///
/// Revision 2 MINUS `first_packet`, which it announced, PLUS
/// `anchor_intervals` and the `first` / `last` / `records` its entries carry.
///
/// Written out and NOT aliased, unlike revision 2: an alias cannot express a
/// removal, and the removal is the half a consumer reading by name breaks on.
/// [`audit`] compares consecutive rows as sets precisely so that diff is
/// visible in the source rather than inferred.
///
/// MEASURED, like every set here: `the_census_documents_key_set_is_pinned`
/// printed what the document emits and this was filled from that printout.
pub const CENSUS_R3_KEYS: &[&str] = &[
    "a",
    "a_to_b",
    "addr",
    "admissible",
    "aggregate",
    "anchor_intervals",
    "anchors_exact",
    "answers",
    "answers_in_scope",
    "asked_at",
    "asker",
    "asks",
    "at_most_bytes",
    "attributed_bytes",
    "b",
    "b_to_a",
    "by_kind",
    "bytes",
    "cancelled_at",
    "caps",
    "children",
    "closed_at",
    "completed",
    "completion",
    "consistent",
    "contradictions",
    "count",
    "declaration",
    "declarations",
    "declared",
    "declared_at",
    "declarer",
    "declarer_zid",
    "dels",
    "descriptors",
    "document",
    "dropped_by_limits",
    "elsewhere",
    "errs",
    "evidence",
    "exchanges",
    "first",
    "first_anchor",
    "first_reply",
    "flow",
    "flows",
    "frames",
    "frames_per_flow",
    "gaps",
    "halted_batches",
    "hello",
    "high",
    "id",
    "inadmissible",
    "init",
    "interests",
    "join",
    "judged",
    "keyexpr",
    "keyexprs",
    "keys",
    "kind",
    "last",
    "last_anchor",
    "links",
    "liveliness_token",
    "locators",
    "low",
    "matched",
    "max_flows_per_table",
    "max_ms",
    "max_scout_askers",
    "mean_ms",
    "messages",
    "min_ms",
    "mismatched",
    "mode",
    "name",
    "narrowed_by_selector",
    "nodes",
    "non_monotonic",
    "not_as_declared",
    "offset_space",
    "orphan_answers",
    "orphan_responses",
    "orphan_withdrawals",
    "payload_bytes",
    "payload_bytes_ceiling",
    "payloads",
    "port",
    "prefix",
    "puts",
    "queries",
    "queryable",
    "queryables",
    "records",
    "rejected",
    "replies",
    "requests",
    "restricted",
    "revision",
    "rows",
    "scout",
    "scout_askers",
    "selection",
    "share_bp",
    "silent",
    "skipped",
    "skipped_packets",
    "solicited_by",
    "source_ahead_of_observer",
    "stream_bytes",
    "stream_bytes_per_direction",
    "subscriber",
    "subscribers",
    "subtrees",
    "tokens",
    "total_ms",
    "total_payload_bytes",
    "totals",
    "unanswered",
    "unattributed_bytes",
    "unattributed_records",
    "unattributed_requests",
    "unclaimed",
    "unclaimed_exact",
    "unclosed",
    "undecidable",
    "undecided",
    "undeclarations",
    "undecompressible_batches",
    "unjudged_answers",
    "unknown_ids",
    "unlocatable_records",
    "unmeasured_payloads",
    "unparsed_bytes",
    "unread",
    "unresolvable_fragments",
    "unresolved",
    "unresolved_declarations",
    "unresolved_records",
    "unsized_payloads",
    "unstamped",
    "walked_records",
    "whatami",
    "wire_bytes",
    "withdrawn_at",
    "zid",
];
/// The field document's key set at revision 1.
///
/// Taken over `census_json::fed_tests::every_plane_capture_with_file` — the
/// RICH fixture, so the row renderers are reached rather than one KeepAlive's
/// worth of them. `declarations: None`: a payload map is the operator's input
/// rather than the capture's, so the keys it adds belong to a revision that
/// declares them and not to whichever fixture passed one.
pub const FIELDS_R1_KEYS: &[&str] = &[
    "addr",
    "caps",
    "capture_reread",
    "datagram_flows",
    "direction",
    "document",
    "dropped_by_limits",
    "end",
    "fields",
    "flow",
    "flows",
    "frames",
    "frames_per_flow",
    "high",
    "kind",
    "low",
    "max_flows_per_table",
    "max_scout_askers",
    "message_at",
    "messages",
    "name",
    "offset_space",
    "omitted",
    "payload_mapping",
    "payload_mapping_counts_exact",
    "payload_refusals",
    "port",
    "revision",
    "scout_askers",
    "shown",
    "skipped",
    "skipped_packets",
    "start",
    "stream_bytes",
    "stream_bytes_per_direction",
    "stream_flows",
    "value",
];
/// The census document's key set at revision 4 — revision 3's, unchanged.
///
/// An ALIAS, the way `CENSUS_R2_KEYS` was an alias of revision 1's: revision 4
/// moves for the VALUE FAMILIES it declares, not for a key. Spelled as an alias
/// rather than copied, because a copy of an unchanged set is a second place for
/// it to drift.
pub const CENSUS_R4_KEYS: &[&str] = CENSUS_R3_KEYS;

/// The value families the census document declares at revision 4.
///
/// Every one is joined to a compiler-bound walk by
/// `the_declared_value_families_match_the_librarys_own_vocabularies`:
/// [`INTEREST_KIND_R4`] to `InterestKind::names`, [`INTEREST_MODE_R4`] to
/// `InterestMode::names`, [`ANCHOR_SPACE_R4`] to `AnchorSpace::names`, and both
/// endpoint keys to `census_json::direction_names`.
///
/// ⚠ R2176 — THE CARDINAL IS GONE FROM THIS PARAGRAPH ON PURPOSE. It read
/// "Five, and every one is joined ..." and was true; the same sentence one
/// constant down read "Three" over a five-element slice, because R2175 widened
/// that list and left its prose. A number written beside the list it counts is
/// a second copy with nothing joining it to the first, and this one was correct
/// only by luck of not having moved yet. The slice IS the count.
///
/// ⚠ `kind` IS NOT THE SAME FAMILY AS THE FIELD DOCUMENT'S `kind`, which is why
/// families are declared per DOCUMENT rather than globally: here it is the sort
/// of declaration a row describes, there it is the sort of value a walked field
/// holds. One key name, two closed sets, two documents.
pub const CENSUS_R4_FAMILIES: &[ValueFamily] = &[
    ValueFamily {
        key: "asker",
        values: DIRECTION_R4,
    },
    ValueFamily {
        key: "declarer",
        values: DIRECTION_R4,
    },
    ValueFamily {
        key: "kind",
        values: INTEREST_KIND_R4,
    },
    ValueFamily {
        key: "mode",
        values: INTEREST_MODE_R4,
    },
    ValueFamily {
        key: "offset_space",
        values: ANCHOR_SPACE_R4,
    },
];

/// `kind` on an interest row, at census revision 4 — SORTED.
///
/// ⚠ Note what the fixtures never produce: `liveliness_token`. A vocabulary
/// taken from what a capture reaches would have declared two words and left the
/// third to arrive unannounced, which is the consumer-goldens failure item 552
/// is about. It is declared because the ENUM has it.
pub const INTEREST_KIND_R4: &[&str] = &["liveliness_token", "queryable", "subscriber"];

/// `mode` on an interest row, at census revision 4 — all four, though the
/// fixtures reach only `current`.
pub const INTEREST_MODE_R4: &[&str] = &["current", "current_future", "final", "future"];

/// `offset_space`, at census revision 4. Which coordinate the anchors are in,
/// and the reason a consumer must switch rather than add: one is a packet index
/// and the other a byte offset.
pub const ANCHOR_SPACE_R4: &[&str] = &["packet", "stream_byte"];

/// A flow endpoint, at census revision 4. `asker`, `declarer`, `direction` and
/// `space` all carry it.
pub const DIRECTION_R4: &[&str] = &["a", "b"];

/// The census document's key set at revision 5 — revision 4's, plus `planes`.
///
/// Written out rather than aliased, because the set MOVED: the envelope now
/// carries the plane list, so `planes` is a key of this document. MEASURED like
/// every other set here — `the_census_documents_key_set_is_pinned` printed what
/// it saw and this was filled from that printout, which is item 400's
/// prescription and the reason no list in this file is a transcription.
pub const CENSUS_R5_KEYS: &[&str] = &[
    "a",
    "a_to_b",
    "addr",
    "admissible",
    "aggregate",
    "anchor_intervals",
    "anchors_exact",
    "answers",
    "answers_in_scope",
    "asked_at",
    "asker",
    "asks",
    "at_most_bytes",
    "attributed_bytes",
    "b",
    "b_to_a",
    "by_kind",
    "bytes",
    "cancelled_at",
    "caps",
    "children",
    "closed_at",
    "completed",
    "completion",
    "consistent",
    "contradictions",
    "count",
    "declaration",
    "declarations",
    "declared",
    "declared_at",
    "declarer",
    "declarer_zid",
    "dels",
    "descriptors",
    "document",
    "dropped_by_limits",
    "elsewhere",
    "errs",
    "evidence",
    "exchanges",
    "first",
    "first_anchor",
    "first_reply",
    "flow",
    "flows",
    "frames",
    "frames_per_flow",
    "gaps",
    "halted_batches",
    "hello",
    "high",
    "id",
    "inadmissible",
    "init",
    "interests",
    "join",
    "judged",
    "keyexpr",
    "keyexprs",
    "keys",
    "kind",
    "last",
    "last_anchor",
    "links",
    "liveliness_token",
    "locators",
    "low",
    "matched",
    "max_flows_per_table",
    "max_ms",
    "max_scout_askers",
    "mean_ms",
    "messages",
    "min_ms",
    "mismatched",
    "mode",
    "name",
    "narrowed_by_selector",
    "nodes",
    "non_monotonic",
    "not_as_declared",
    "offset_space",
    "orphan_answers",
    "orphan_responses",
    "orphan_withdrawals",
    "payload_bytes",
    "payload_bytes_ceiling",
    "payloads",
    "planes",
    "port",
    "prefix",
    "puts",
    "queries",
    "queryable",
    "queryables",
    "records",
    "rejected",
    "replies",
    "requests",
    "restricted",
    "revision",
    "rows",
    "scout",
    "scout_askers",
    "selection",
    "share_bp",
    "silent",
    "skipped",
    "skipped_packets",
    "solicited_by",
    "source_ahead_of_observer",
    "stream_bytes",
    "stream_bytes_per_direction",
    "subscriber",
    "subscribers",
    "subtrees",
    "tokens",
    "total_ms",
    "total_payload_bytes",
    "totals",
    "unanswered",
    "unattributed_bytes",
    "unattributed_records",
    "unattributed_requests",
    "unclaimed",
    "unclaimed_exact",
    "unclosed",
    "undecidable",
    "undecided",
    "undeclarations",
    "undecompressible_batches",
    "unjudged_answers",
    "unknown_ids",
    "unlocatable_records",
    "unmeasured_payloads",
    "unparsed_bytes",
    "unread",
    "unresolvable_fragments",
    "unresolved",
    "unresolved_declarations",
    "unresolved_records",
    "unsized_payloads",
    "unstamped",
    "walked_records",
    "whatami",
    "wire_bytes",
    "withdrawn_at",
    "zid",
];

/// The value families the census document declares at revision 5 — revision
/// 4's, unchanged.
///
/// An ALIAS: revision 5 moves for a KEY, and a copy of an unmoved vocabulary
/// would be a second place for it to drift. Same argument `CENSUS_R2_KEYS` made
/// one axis over.
pub const CENSUS_R5_FAMILIES: &[ValueFamily] = CENSUS_R4_FAMILIES;

/// The census document's PLANES at revision 5 — sorted.
///
/// R2180 (open-debt item 554). Five, and the slice is the count: R2176 struck a
/// cardinal written beside a list in this file for exactly the reason this list
/// exists, and repeating one here would be the same defect one row down.
///
/// SORTED rather than in the order the document emits them, which is the
/// invariant every other list in this table holds and for the same reason
/// [`audit`] gives about the key set: a comparison between two revisions must
/// not depend on the order someone typed them in.
///
/// ⚠ NOT a hand-picked list, and that distinction is the whole of item 554.
/// `the_declared_planes_are_the_planes_the_document_emits` derives the plane set
/// from an EMITTED census — the top-level keys that carry `narrowed_by_selector`
/// or arrive as `null` — and requires it to equal this one, in a build that
/// feeds every plane and in a build that feeds none. A sixth plane added
/// without this row moving is a red, and so is a name here the document does not
/// emit.
pub const CENSUS_R5_PLANES: &[&str] = &["exchanges", "interests", "keyexprs", "nodes", "payloads"];

/// The census document's key set at revision 6 — revision 5's, unchanged.
///
/// An ALIAS, on [`CENSUS_R4_KEYS`]' rule: revision 6 moves for the CARRIES axis
/// and touches no key.
pub const CENSUS_R6_KEYS: &[&str] = CENSUS_R5_KEYS;
/// The census document's value families at revision 6 — revision 5's, unchanged.
pub const CENSUS_R6_FAMILIES: &[ValueFamily] = CENSUS_R5_FAMILIES;
/// The census document's planes at revision 6 — revision 5's, unchanged.
pub const CENSUS_R6_PLANES: &[&str] = CENSUS_R5_PLANES;

/// What each census family's WORD decides about the keys beside it, at
/// revision 6.
///
/// R2184 (open-debt item 556). All five are [`CarriesShape::Passenger`], and
/// the uniformity is the finding rather than a shrug: this document's planes
/// are rendered by straight-line row emitters that write every key on every row
/// and put `null` where a value does not apply, so no word of any of these five
/// can remove a key. `interests_json` says so in six separate comments
/// (`"null and not the declaration's own anchor"`, `"an empty string is a
/// value"`, …) and until this row nothing measured it.
///
/// ⚠ SORTED BY KEY, which [`audit`] refuses to take on trust, and covering
/// EVERY family revision 6 declares — a family missing here is a key a consumer
/// switches on with no answer about what comes with it.
pub const CENSUS_R6_CARRIES: &[KeyCarries] = &[
    KeyCarries {
        key: "asker",
        shape: CarriesShape::Passenger,
    },
    KeyCarries {
        key: "declarer",
        shape: CarriesShape::Passenger,
    },
    KeyCarries {
        key: "kind",
        shape: CarriesShape::Passenger,
    },
    KeyCarries {
        key: "mode",
        shape: CarriesShape::Passenger,
    },
    KeyCarries {
        key: "offset_space",
        shape: CarriesShape::Passenger,
    },
];

/// The field document's key set at revision 2.
///
/// MEASURED, never transcribed — item 400's prescription, and here it had to be
/// taken from a population that no single capture produces:
/// `the_field_documents_payload_plane_is_pinned_over_every_arm` renders every
/// `PayloadDecoding`, `RefusedUnder` and `Misbound` arm and prints the union it
/// sees, and this list was filled from that printout.
pub const FIELDS_R2_KEYS: &[&str] = &[
    "addr",
    "caps",
    "capture_reread",
    "datagram_flows",
    // R2025 (item 285) and R2170 (item 546) both added a key HERE and neither
    // moved a number, because revision 1 had never covered this subtree.
    "declaration_checked",
    "declared",
    "descriptor_bytes",
    "despite_encoding",
    "direction",
    "document",
    "dropped_by_limits",
    "end",
    "example",
    "fields",
    "flow",
    "flows",
    "format",
    "frames",
    "frames_per_flow",
    "high",
    "keyexpr",
    "kind",
    "low",
    "max_flows_per_table",
    "max_scout_askers",
    "message_at",
    "messages",
    "name",
    "note",
    "offset_space",
    "omitted",
    "path",
    "payload_decode",
    "payload_mapping",
    "payload_mapping_counts_exact",
    "payload_refusals",
    "port",
    "revision",
    "samples",
    "scout_askers",
    "shown",
    "skipped",
    "skipped_packets",
    "start",
    "state",
    "stream_bytes",
    "stream_bytes_per_direction",
    "stream_flows",
    "under",
    "value",
    "why",
    "wrong",
];

/// The value families the field document declares at revision 2.
///
/// Every one is joined to a compiler-bound walk by
/// `the_declared_value_families_match_the_librarys_own_vocabularies`, so a word
/// added to a walk cannot ship until a revision here carries it:
/// [`PAYLOAD_STATE_R2`] to `PayloadDecoding::STATES`, [`REFUSED_UNDER_R2`] to
/// `RefusedUnder::names`, [`MISBOUND_R2`] to `Misbound::names`,
/// [`ANCHOR_SPACE_FIELDS_R2`] to `AnchorSpace::names` and
/// [`DIRECTION_FIELDS_R2`] to `census_json::direction_names`.
///
/// ⚠ R2176 — THIS PARAGRAPH WAS WRONG FROM THE ROUND THAT WROTE IT. It said
/// "Three, and they are the payload plane's", naming only the first three
/// constants above, while the slice below it has held FIVE since that same
/// commit: R2175 added `direction` and `offset_space` here for the same-seam
/// residue and moved the list without moving the sentence. Both halves of the
/// error are the same shape — a count and a membership restated in prose beside
/// the thing that defines them. Nothing in this workspace measures either, which
/// is open-debt item 530; what is done instead is to stop writing the count at
/// all and to keep the membership as the JOINT it actually is, one constant to
/// one walk, so a family added without a walk has no sentence to hide in.
pub const FIELDS_R2_FAMILIES: &[ValueFamily] = &[
    ValueFamily {
        key: "direction",
        values: DIRECTION_FIELDS_R2,
    },
    ValueFamily {
        key: "offset_space",
        values: ANCHOR_SPACE_FIELDS_R2,
    },
    ValueFamily {
        key: "state",
        values: PAYLOAD_STATE_R2,
    },
    ValueFamily {
        key: "under",
        values: REFUSED_UNDER_R2,
    },
    ValueFamily {
        key: "wrong",
        values: MISBOUND_R2,
    },
];

/// The field document's key set at revision 3 — revision 2's, unchanged.
///
/// An ALIAS, the way [`CENSUS_R4_KEYS`] is one: revision 3 moves for the value
/// family it declares, not for a key. `kind` has been in this set since
/// revision 1 — which is the whole of item 555, one sentence: the KEY was
/// pinned from the beginning and the closed set of words inside it was declared
/// by nothing.
pub const FIELDS_R3_KEYS: &[&str] = FIELDS_R2_KEYS;

/// The value families the field document declares at revision 3.
///
/// Revision 2's five plus `kind`, joined to `FieldValue::kind_words` by
/// `the_declared_value_families_match_the_librarys_own_vocabularies` like every
/// other row here. Sorted by key, which [`audit`] refuses to take on trust.
pub const FIELDS_R3_FAMILIES: &[ValueFamily] = &[
    ValueFamily {
        key: "direction",
        values: DIRECTION_FIELDS_R2,
    },
    ValueFamily {
        key: "kind",
        values: FIELD_VALUE_KIND_R3,
    },
    ValueFamily {
        key: "offset_space",
        values: ANCHOR_SPACE_FIELDS_R2,
    },
    ValueFamily {
        key: "state",
        values: PAYLOAD_STATE_R2,
    },
    ValueFamily {
        key: "under",
        values: REFUSED_UNDER_R2,
    },
    ValueFamily {
        key: "wrong",
        values: MISBOUND_R2,
    },
];

/// `fields[].kind` at field-document revision 3 — SORTED, which is why it does
/// not read in `FieldValue::kind_words`' walk order.
///
/// R2182 (open-debt item 555). The discriminant of the field TREE, and the one
/// switchable key in this document that shipped with no vocabulary behind it.
///
/// ⚠ NOT THE SAME FAMILY AS THE CENSUS DOCUMENT'S `kind`, which is why families
/// are declared per document: there it is the sort of declaration an interest
/// row describes ([`INTEREST_KIND_R4`]), here it is the sort of VALUE a walked
/// field holds. One key name, two closed sets, two documents — and a third
/// spelling that is neither, `InboundFrame::kind_name`, which travels under
/// `name` rather than `kind`. Three near-namesakes were what made this item's
/// own filing miscount twice before it was written.
///
/// Written out rather than pointing at the walk, for the reason
/// [`ValueFamily::values`] gives: a table that read the walk would widen with
/// it, and then the revision would never have to move.
pub const FIELD_VALUE_KIND_R3: &[&str] = &[
    "bits", "bytes", "flag", "label", "nested", "opaque", "text", "uint",
];

/// The field document's key set at revision 4 — revision 3's, unchanged.
///
/// An ALIAS, on [`CENSUS_R4_KEYS`]' rule: revision 4 moves for the CARRIES axis
/// and touches no key. The keys it describes have all been in this set since
/// revision 2; what was undeclared is which of them arrive TOGETHER.
pub const FIELDS_R4_KEYS: &[&str] = FIELDS_R3_KEYS;
/// The field document's value families at revision 4 — revision 3's, unchanged.
pub const FIELDS_R4_FAMILIES: &[ValueFamily] = FIELDS_R3_FAMILIES;

/// What each field-document family's WORD decides about the keys beside it, at
/// revision 4.
///
/// R2184 (open-debt item 556) — the row the item was filed for, and the one
/// that MEASURED more than the item claimed. Three discriminants, not two.
///
/// The key sets below are MEASURED, never transcribed, on the rule the key-set
/// tables at the top of this file state: each was printed by
/// `the_declared_carries_axis_is_the_one_the_emitters_render` over the arms it
/// renders, and pasted back.
///
/// ⚠ The `keys` are the object's WHOLE companion set, envelope included, and
/// not a diff against a sibling word. A consumer parses the object it is
/// handed: `opaque` carries `end`, `name` and `start`; `bits` carries those
/// three and `value`. Writing only the difference would make the list unusable
/// for the reader it exists for and would hide the case that has no difference.
pub const FIELDS_R4_CARRIES: &[KeyCarries] = &[
    KeyCarries {
        key: "direction",
        shape: CarriesShape::Passenger,
    },
    // The discriminant of the field TREE. `opaque` is the word that carries no
    // companion at all, and the consuming surface that filed item 555 lost it
    // outright; a consumer handed the eight words and no map writes an `opaque`
    // arm and reads `value` out of an object that has none.
    KeyCarries {
        key: "kind",
        shape: CarriesShape::Discriminant(FIELD_VALUE_KIND_CARRIES_R4),
    },
    // THE THIRD DISCRIMINANT, and the one no reading of a `match` would have
    // found: the word is chosen by which ROW EMITTER ran. A datagram row
    // numbers its message with a `packet` INDEX and a stream row with a
    // `message_at` BYTE OFFSET, and only the stream row carries the payload
    // plane at all.
    KeyCarries {
        key: "offset_space",
        shape: CarriesShape::Discriminant(FIELD_OFFSET_SPACE_CARRIES_R4),
    },
    KeyCarries {
        key: "state",
        shape: CarriesShape::Discriminant(PAYLOAD_STATE_CARRIES_R4),
    },
    KeyCarries {
        key: "under",
        shape: CarriesShape::Passenger,
    },
    KeyCarries {
        key: "wrong",
        shape: CarriesShape::Passenger,
    },
];

/// Every shape each `fields[].kind` word's object takes, at field-document
/// revision 4.
///
/// R2184 (open-debt item 556). `name`, `start` and `end` are the envelope every
/// field object carries; the fourth key is the one the word decides — `value`
/// for the six scalar words, `fields` for `nested`, and none at all for
/// `opaque`, whose span is the whole answer.
///
/// One shape each: this object is written by a single `match` whose arm the
/// word IS, so nothing else can vary it.
pub const FIELD_VALUE_KIND_CARRIES_R4: &[WordCarries] = &[
    WordCarries {
        word: "bits",
        shapes: &[&["end", "name", "start", "value"]],
    },
    WordCarries {
        word: "bytes",
        shapes: &[&["end", "name", "start", "value"]],
    },
    WordCarries {
        word: "flag",
        shapes: &[&["end", "name", "start", "value"]],
    },
    WordCarries {
        word: "label",
        shapes: &[&["end", "name", "start", "value"]],
    },
    WordCarries {
        word: "nested",
        shapes: &[&["end", "fields", "name", "start"]],
    },
    WordCarries {
        word: "opaque",
        shapes: &[&["end", "name", "start"]],
    },
    WordCarries {
        word: "text",
        shapes: &[&["end", "name", "start", "value"]],
    },
    WordCarries {
        word: "uint",
        shapes: &[&["end", "name", "start", "value"]],
    },
];

/// Every shape each `fields[].offset_space` word's object takes, at
/// field-document revision 4.
///
/// R2184 (open-debt item 556). The two ROW EMITTERS, stated as the contract a
/// consumer reads: a `packet` row numbers its message by INDEX and never
/// carries the payload plane, a `stream_byte` row numbers it by OFFSET and
/// carries `message_at` always and `payload_decode` only when the caller
/// supplied a format map.
///
/// TWO SHAPES on `stream_byte`, and they are why [`WordCarries::shapes`] is a
/// list. `message_at` is decided by the word and `payload_decode` is decided by
/// the caller, and a single set could state only one of those two facts.
pub const FIELD_OFFSET_SPACE_CARRIES_R4: &[WordCarries] = &[
    WordCarries {
        word: "packet",
        shapes: &[&["direction", "fields", "name", "packet"]],
    },
    WordCarries {
        word: "stream_byte",
        shapes: &[
            &["direction", "fields", "message_at", "name"],
            &[
                "direction",
                "fields",
                "message_at",
                "name",
                "payload_decode",
            ],
        ],
    },
];

/// Every shape each `payload_decode.state` word's object takes, at
/// field-document revision 4.
///
/// R2184 (open-debt item 556) — eight words over six distinct shapes, which is
/// the widest spread in either document and the measurement that made item 555
/// file this as an axis rather than an exception for `opaque`.
///
/// ⚠ `encoding_mismatch` carries FOUR keys and not five. Item 556's own filing
/// said it carries `refused`'s three plus `declared` and `declaration_checked`;
/// the render says `why` is not among them. That is the third of this seam's
/// prose measurements to be refuted by asking the emitter, which is why the
/// item says to derive the population rather than list it.
pub const PAYLOAD_STATE_CARRIES_R4: &[WordCarries] = &[
    WordCarries {
        word: "decoded",
        shapes: &[&["despite_encoding", "fields", "format", "keyexpr"]],
    },
    WordCarries {
        word: "encoding_mismatch",
        shapes: &[&["declaration_checked", "declared", "format", "keyexpr"]],
    },
    WordCarries {
        word: "keyexpr_unresolved",
        shapes: &[&[]],
    },
    WordCarries {
        word: "no_payload",
        shapes: &[&[]],
    },
    WordCarries {
        word: "no_rule",
        shapes: &[&["keyexpr"]],
    },
    WordCarries {
        word: "no_rules",
        shapes: &[&[]],
    },
    WordCarries {
        word: "not_on_the_wire",
        shapes: &[&["descriptor_bytes"]],
    },
    WordCarries {
        word: "refused",
        shapes: &[&["format", "keyexpr", "why"]],
    },
];

/// `payload_decode.state` at field-document revision 2 — SORTED, which is why
/// it does not read in `PayloadDecoding::STATES`' order.
///
/// The eight words R2170 left at eight. Written out rather than pointing at
/// `PayloadDecoding::STATES`: a table that read the constant would widen with
/// it, and then the revision would never have to move — which is precisely the
/// state item 552 measured.
pub const PAYLOAD_STATE_R2: &[&str] = &[
    "decoded",
    "encoding_mismatch",
    "keyexpr_unresolved",
    "no_payload",
    "no_rule",
    "no_rules",
    "not_on_the_wire",
    "refused",
];

/// `payload_refusals[].under` at field-document revision 2.
pub const REFUSED_UNDER_R2: &[&str] = &["corroborated", "refuted", "unclaimed"];

/// `offset_space` at FIELD-document revision 2.
///
/// ⚠ SPELLED OUT AGAIN rather than aliasing [`ANCHOR_SPACE_R4`], and the
/// duplication is the mechanism rather than an oversight. Two documents emit
/// this key and a consumer pins them SEPARATELY — that is the whole reason
/// item 509 chose a revision per document over one library-wide number. If both
/// rows pointed at one constant, teaching `AnchorSpace` a third word would
/// widen both vocabularies in one edit and neither revision would have to move:
/// the pin would follow its subject, which is the defect this table exists to
/// stop. Duplicated, a widening costs two edits and two revision bumps, which
/// is two notices to two sets of readers.
pub const ANCHOR_SPACE_FIELDS_R2: &[&str] = &["packet", "stream_byte"];

/// A flow endpoint at FIELD-document revision 2 — spelled out again, for the
/// reason [`ANCHOR_SPACE_FIELDS_R2`] gives.
pub const DIRECTION_FIELDS_R2: &[&str] = &["a", "b"];

/// `payload_mapping[].wrong` at field-document revision 2.
pub const MISBOUND_R2: &[&str] = &["publisher", "rule"];

/// The summary document's key set at revision 1.
///
/// The largest of the six, because `report::health_json` rides inside it: the
/// stream-health, checksum and encapsulation counters are the summary's keys as
/// far as a consumer is concerned, whichever module renders them.
pub const SUMMARY_R1_KEYS: &[&str] = &[
    "bytes_absent",
    "caps",
    "capture_reported_drops",
    "completed",
    "datagram_flows",
    "desyncs",
    "document",
    "dropped_by_limits",
    "duplicates",
    "encapsulation_depth_bound",
    "encapsulation_too_deep",
    "encapsulations",
    "evicted",
    "expired",
    "flows",
    "fragments",
    "frames",
    "frames_per_flow",
    "framing",
    "gap_bytes_missing",
    "gaps",
    "gaps_forced",
    "gre_payload",
    "gre_payloads",
    "health",
    "held",
    "ip_checksum_absent",
    "ip_checksum_invalid",
    "ip_checksum_valid",
    "ip_fragment_pending",
    "ipv4_fragment",
    "ipv6_extension_chain",
    "ipv6_fragment",
    "link_types",
    "malformed",
    "max_flows_per_table",
    "max_scout_askers",
    "missing",
    "name",
    "not_ip",
    "not_this_protocol",
    "not_transport",
    "not_transport_protos",
    "open",
    "out_of_order",
    "out_of_window",
    "overlapping",
    "partial_overlaps",
    "pieces",
    "recoveries",
    "reserved_headers",
    "resync_skipped_bytes",
    "retransmits",
    "revision",
    "scout_askers",
    "sequence",
    "skipped",
    "skipped_packets",
    "skips",
    "stream_bytes",
    "stream_bytes_per_direction",
    "streams",
    "tcp_flows",
    "too_deep_protos",
    "total",
    "transport_checksum_absent",
    "transport_checksum_invalid",
    "transport_checksum_valid",
    "truncated",
    "tunnel_checksum_absent",
    "tunnel_checksum_invalid",
    "tunnel_checksum_valid",
    "uncorroborated_layers",
    "unfinished",
    "unfinished_bytes",
    "unsupported_link_type",
    "unwalked_encapsulation",
    "vsock_non_payload",
    "without_resolution",
    "ws_desyncs",
    "ws_recoveries",
    "ws_resync_skipped_bytes",
];
/// The summary document's key set at revision 2 — revision 1 plus
/// `inert_counters` (R2121, open-debt item 460).
///
/// MEASURED, like every set here: the pin test in `wz-capi-dissect` printed
/// what the document emits and this was filled from that printout. A
/// hand-extended copy of the 83 names above is the edit R2119 measured going
/// wrong in BOTH directions on a smaller list.
pub const SUMMARY_R2_KEYS: &[&str] = &[
    "bytes_absent",
    "caps",
    "capture_reported_drops",
    "completed",
    "datagram_flows",
    "desyncs",
    "document",
    "dropped_by_limits",
    "duplicates",
    "encapsulation_depth_bound",
    "encapsulation_too_deep",
    "encapsulations",
    "evicted",
    "expired",
    "flows",
    "fragments",
    "frames",
    "frames_per_flow",
    "framing",
    "gap_bytes_missing",
    "gaps",
    "gaps_forced",
    "gre_payload",
    "gre_payloads",
    "health",
    "held",
    "inert_counters",
    "ip_checksum_absent",
    "ip_checksum_invalid",
    "ip_checksum_valid",
    "ip_fragment_pending",
    "ipv4_fragment",
    "ipv6_extension_chain",
    "ipv6_fragment",
    "link_types",
    "malformed",
    "max_flows_per_table",
    "max_scout_askers",
    "missing",
    "name",
    "not_ip",
    "not_this_protocol",
    "not_transport",
    "not_transport_protos",
    "open",
    "out_of_order",
    "out_of_window",
    "overlapping",
    "partial_overlaps",
    "pieces",
    "recoveries",
    "reserved_headers",
    "resync_skipped_bytes",
    "retransmits",
    "revision",
    "scout_askers",
    "sequence",
    "skipped",
    "skipped_packets",
    "skips",
    "stream_bytes",
    "stream_bytes_per_direction",
    "streams",
    "tcp_flows",
    "too_deep_protos",
    "total",
    "transport_checksum_absent",
    "transport_checksum_invalid",
    "transport_checksum_valid",
    "truncated",
    "tunnel_checksum_absent",
    "tunnel_checksum_invalid",
    "tunnel_checksum_valid",
    "uncorroborated_layers",
    "unfinished",
    "unfinished_bytes",
    "unsupported_link_type",
    "unwalked_encapsulation",
    "vsock_non_payload",
    "without_resolution",
    "ws_desyncs",
    "ws_recoveries",
    "ws_resync_skipped_bytes",
];

/// The summary document's key set at revision 3 — revision 2 plus
/// `undefined_mandatory_exts` and `unaccounted_batch_bytes` (R2122, open-debt
/// item 238).
///
/// Those two were never NEW: the capture report had carried them since
/// R311y624 and the health document, which is what this door hands back, had
/// not. Sharing one emitter for the `framing` group is what brought them here,
/// so this revision records a document that stopped disagreeing with its
/// sibling rather than one that grew.
///
/// MEASURED, like every set here: the pin in `wz-capi-dissect` printed what
/// the document emits and this was filled from that printout.
pub const SUMMARY_R3_KEYS: &[&str] = &[
    "bytes_absent",
    "caps",
    "capture_reported_drops",
    "completed",
    "datagram_flows",
    "desyncs",
    "document",
    "dropped_by_limits",
    "duplicates",
    "encapsulation_depth_bound",
    "encapsulation_too_deep",
    "encapsulations",
    "evicted",
    "expired",
    "flows",
    "fragments",
    "frames",
    "frames_per_flow",
    "framing",
    "gap_bytes_missing",
    "gaps",
    "gaps_forced",
    "gre_payload",
    "gre_payloads",
    "health",
    "held",
    "inert_counters",
    "ip_checksum_absent",
    "ip_checksum_invalid",
    "ip_checksum_valid",
    "ip_fragment_pending",
    "ipv4_fragment",
    "ipv6_extension_chain",
    "ipv6_fragment",
    "link_types",
    "malformed",
    "max_flows_per_table",
    "max_scout_askers",
    "missing",
    "name",
    "not_ip",
    "not_this_protocol",
    "not_transport",
    "not_transport_protos",
    "open",
    "out_of_order",
    "out_of_window",
    "overlapping",
    "partial_overlaps",
    "pieces",
    "recoveries",
    "reserved_headers",
    "resync_skipped_bytes",
    "retransmits",
    "revision",
    "scout_askers",
    "sequence",
    "skipped",
    "skipped_packets",
    "skips",
    "stream_bytes",
    "stream_bytes_per_direction",
    "streams",
    "tcp_flows",
    "too_deep_protos",
    "total",
    "transport_checksum_absent",
    "transport_checksum_invalid",
    "transport_checksum_valid",
    "truncated",
    "tunnel_checksum_absent",
    "tunnel_checksum_invalid",
    "tunnel_checksum_valid",
    "unaccounted_batch_bytes",
    "uncorroborated_layers",
    "undefined_mandatory_exts",
    "unfinished",
    "unfinished_bytes",
    "unsupported_link_type",
    "unwalked_encapsulation",
    "vsock_non_payload",
    "without_resolution",
    "ws_desyncs",
    "ws_recoveries",
    "ws_resync_skipped_bytes",
];

/// The readable-surfaces document's key set at revision 1.
pub const READABLE_SURFACES_R1_KEYS: &[&str] = &[
    "document",
    "doors",
    "ext_bodies",
    "link_types",
    "name",
    "revision",
    "subsumed_by",
    "z64",
    "zbuf",
];
/// The readable-surfaces document's key set at revision 2.
///
/// R2114 (open-debt item 237) — revision 1 plus `payload_field_types`. Written
/// out rather than built from the row above, because a key set derived from
/// its predecessor cannot express a removal, and [`audit`] compares the two as
/// SETS: the whole point of the pin is that the diff is visible in the source.
pub const READABLE_SURFACES_R2_KEYS: &[&str] = &[
    "document",
    "doors",
    "ext_bodies",
    "link_types",
    "name",
    "payload_field_types",
    "revision",
    "subsumed_by",
    "z64",
    "zbuf",
];
/// The readable-surfaces document's key set at revision 3.
///
/// R2175 (open-debt item 552) — revision 2 plus `value_families` and the two
/// keys its rows carry, `key` and `values`. The rows also carry `name` and
/// `revision`, which this document already emits: reused deliberately, the way
/// `doors[]` already reuses `name`, so a reader learns one spelling for "which
/// document" and one for "which revision of it".
pub const READABLE_SURFACES_R3_KEYS: &[&str] = &[
    "document",
    "doors",
    "ext_bodies",
    "key",
    "link_types",
    "name",
    "payload_field_types",
    "revision",
    "subsumed_by",
    "value_families",
    "values",
    "z64",
    "zbuf",
];

/// The readable-surfaces catalogue's key set at revision 4.
///
/// R2184 (open-debt item 556) — revision 3's plus the three the CARRIES axis
/// contributes: `carries` on every `value_families` row, and `word` / `shapes`
/// on the rows under it.
///
/// Spelled out rather than built from [`READABLE_SURFACES_R3_KEYS`], on the
/// rule [`ValueFamily::values`]' doc gives about a pin that follows its
/// subject.
pub const READABLE_SURFACES_R4_KEYS: &[&str] = &[
    "carries",
    "document",
    "doors",
    "ext_bodies",
    "key",
    "link_types",
    "name",
    "payload_field_types",
    "revision",
    "shapes",
    "subsumed_by",
    "value_families",
    "values",
    "word",
    "z64",
    "zbuf",
];

/// The selector verdict's key set at revision 1, over BOTH branches.
///
/// The UNION of `{ok:true}` and `{ok:false,at,message}`: a pin over one branch
/// would leave the other's keys unwatched, which is a gate that reads green
/// over half a contract.
pub const SELECTOR_DIAGNOSE_R1_KEYS: &[&str] =
    &["at", "document", "message", "name", "ok", "revision"];
/// The declaration verdict's key set at revision 1, over BOTH branches.
pub const DECLARATIONS_DIAGNOSE_R1_KEYS: &[&str] = &[
    "document",
    "installed",
    "line",
    "message",
    "name",
    "ok",
    "revision",
    "text",
];

/// The three keys the envelope itself contributes to every document.
///
/// Named rather than repeated into six tables: they are the same three keys
/// for every document by construction, and a table that spelled them out six
/// times would be six places to get them wrong.
pub const ENVELOPE_KEYS: &[&str] = &["document", "name", "revision"];

/// The newest shape recorded for `document`, or `None` for a name this library
/// does not emit.
pub fn newest(document: &str) -> Option<&'static DocumentShape> {
    DOCUMENT_HISTORY
        .iter()
        .filter(|s| s.document == document)
        .max_by_key(|s| s.revision)
}

/// The revision `document` emits today.
pub fn revision(document: &str) -> Option<u32> {
    newest(document).map(|s| s.revision)
}

/// Write the envelope every emitted document opens with.
///
/// FIRST KEY IN THE DOCUMENT at every call site, so a consumer reads the
/// revision without walking the body — which is the difference between a
/// number it can branch on and a number it finds after it has already parsed
/// the shape it was trying to check.
///
/// A document name this library does not know is a programming error and is
/// written as `revision: 0`, a value [`audit`] refuses, rather than being
/// silently omitted: a document with no envelope is exactly the state item 509
/// measured, and it must not be reachable by a typo.
pub fn envelope_into(document: &str, out: &mut String) {
    out.push_str("\"document\":{\"name\":\"");
    out.push_str(document);
    let _ = write!(out, "\",\"revision\":{}", revision(document).unwrap_or(0));
    // R2180 (open-debt item 554) — WHICH OF THIS DOCUMENT'S TOP-LEVEL KEYS ARE
    // PLANES, written into the document rather than answered by a second door,
    // so the list cannot be paired with a document from a different build.
    //
    // Omitted entirely for a document that declares none, and that silence is
    // not the ambiguity this key exists to remove: a document with no planes
    // has no plane to be ambiguous ABOUT, and
    // `every_top_level_null_is_a_declared_plane` is what holds that true rather
    // than the observation that it happens to be today.
    //
    // ⚠ R2181 — that sentence was written when the gate behind it checked only
    // the `null` shape, so the justification reached further than the gate did:
    // a silent document could have grown a `narrowed_by_selector` key and no
    // arm would have looked. The gate now derives every plane shape over all
    // six documents (`emitted_planes`), which is what the silence rests on.
    let planes = newest(document).map(|s| s.planes).unwrap_or(&[]);
    if !planes.is_empty() {
        out.push_str(",\"planes\":[");
        for (i, plane) in planes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "\"{plane}\"");
        }
        out.push(']');
    }
    out.push('}');
}

/// The whole envelope as its own string, for a caller building a document with
/// `format!` rather than by pushing.
pub fn envelope(document: &str) -> String {
    let mut out = String::new();
    envelope_into(document, &mut out);
    out
}

/// Every value family this library emits today, as the rows of a JSON array —
/// WITHOUT the surrounding brackets, so a caller places it under whatever key
/// its own document uses.
///
/// R2175 (open-debt item 552) — the third half of the answer, and the one a
/// consumer can act on without redeploying. The revision pin tells a reader
/// pinned to an old shape THAT something moved; this tells a reader at runtime
/// WHAT the vocabulary is, so a program can compare the words it was written
/// against with the words this build emits and say which ones it does not know.
/// That is the `payload_field_types` argument (R2114, item 237) one axis over:
/// a list copied into a consumer's own switch ages the moment this one grows,
/// and the alternative to asking the library is reading its source.
///
/// Rendered from [`DOCUMENT_HISTORY`]'s NEWEST row per document, because that is
/// what the library emits; the older rows are history a consumer reads by
/// pinning, not by asking.
pub fn value_families_into(out: &mut String) {
    let mut names: Vec<&str> = DOCUMENT_HISTORY.iter().map(|r| r.document).collect();
    names.sort_unstable();
    names.dedup();
    let mut first = true;
    for name in names {
        let Some(shape) = newest(name) else { continue };
        for family in shape.families {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(
                out,
                "{{\"name\":\"{name}\",\"revision\":{},\"key\":\"{}\",\"values\":[",
                shape.revision, family.key
            );
            for (i, value) in family.values.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "\"{value}\"");
            }
            // R2184 (open-debt item 556) — THE THIRD AXIS, beside the words it
            // qualifies rather than in a door of its own. `null` for a family
            // whose word decides nothing, on this document set's own rule that
            // an inapplicable value is written and not omitted: a consumer that
            // found no key here could not tell "this build does not answer that"
            // from "this key is a passenger", which is item 554's shape one
            // document over.
            //
            // Always emitted at this revision, so `carries` is never a key a
            // reader has to test for. `audit` is what makes that safe to rely
            // on: at the newest revision every declared family has a row.
            out.push_str("],\"carries\":");
            match shape.carries.iter().find(|c| c.key == family.key) {
                Some(KeyCarries {
                    shape: CarriesShape::Discriminant(rows),
                    ..
                }) => {
                    out.push('[');
                    for (i, row) in rows.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        let _ = write!(out, "{{\"word\":\"{}\",\"shapes\":[", row.word);
                        for (j, shape) in row.shapes.iter().enumerate() {
                            if j > 0 {
                                out.push(',');
                            }
                            out.push('[');
                            for (k, key) in shape.iter().enumerate() {
                                if k > 0 {
                                    out.push(',');
                                }
                                let _ = write!(out, "\"{key}\"");
                            }
                            out.push(']');
                        }
                        out.push_str("]}");
                    }
                    out.push(']');
                }
                Some(KeyCarries {
                    shape: CarriesShape::Passenger,
                    ..
                }) => out.push_str("null"),
                // A family with no row is a programming error and is written as
                // a value NEITHER shape can produce, on `envelope_into`'s rule
                // about `revision: 0`: silence here would read as "passenger",
                // which is a claim, and an undeclared family must not be able
                // to make one by omission.
                None => out.push_str("\"undeclared\""),
            }
            out.push('}');
        }
    }
}

/// Every KEY in a JSON document, in order of appearance, duplicates included.
///
/// A string is a key when the next non-space character after it is a colon.
/// Deliberately not a parser: this crate already has one
/// (`payload::json_wellformed`), and a second would be a second opinion about
/// what JSON is.
///
/// R2100 (open-debt item 509) — moved here from `census_json`'s test module and
/// made `pub`, because the key-set pins now live in TWO crates:
/// `wz-capi-dissect` builds four of the six documents. A copy over there would
/// be a second opinion about what a key is, which is the same argument the
/// paragraph above makes about parsers, one level up.
pub fn json_keys(doc: &str) -> Vec<&str> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j] != b'"' {
            // The escape is what stops a key containing a quote from ending
            // here, which the hostile-string test in `census_json` makes real.
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        if j >= b.len() {
            break;
        }
        let mut k = j + 1;
        while k < b.len() && b[k] == b' ' {
            k += 1;
        }
        if k < b.len() && b[k] == b':' {
            out.push(&doc[start..j]);
        }
        i = j + 1;
    }
    out
}

/// Every `key: "value"` pair in a JSON document where the value is a STRING
/// SCALAR, in order of appearance, duplicates included.
///
/// R2175 (open-debt item 552) — the sibling of [`json_keys`], and the reason it
/// is a sibling rather than a second walker is the argument that function's own
/// doc makes: one opinion about what a key is. This one adds the other half of
/// the pair, because a consumer switches on VALUES and the key-set pin above
/// cannot see them.
///
/// # What it deliberately does not collect
///
/// An ARRAY element is not the value of any key, so `"doors":["a","b"]` yields
/// nothing here. That is not an oversight: a catalogue a consumer ITERATES is
/// not a family it SWITCHES on, and folding the two together would put every
/// keyexpr this library ever printed into the population of things a switch
/// could fall through. [`ValueFamily`] is about the scalar a `switch` reads.
///
/// Escapes are stepped over the same way [`json_keys`] steps over them, so a
/// value containing a quote does not end the scan early.
pub fn json_string_values(doc: &str) -> Vec<(&str, &str)> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    // The end of the string that most recently turned out to be a KEY, so the
    // value scan starts from the colon rather than re-finding it.
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j] != b'"' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        if j >= b.len() {
            break;
        }
        let mut k = j + 1;
        while k < b.len() && b[k] == b' ' {
            k += 1;
        }
        if k >= b.len() || b[k] != b':' {
            i = j + 1;
            continue;
        }
        // Past the colon, to whatever the value opens with.
        let mut v = k + 1;
        while v < b.len() && b[v] == b' ' {
            v += 1;
        }
        if v >= b.len() || b[v] != b'"' {
            // A number, an object, an array or a literal. Not a family.
            i = j + 1;
            continue;
        }
        let vstart = v + 1;
        let mut vend = vstart;
        while vend < b.len() && b[vend] != b'"' {
            vend += if b[vend] == b'\\' { 2 } else { 1 };
        }
        if vend >= b.len() {
            break;
        }
        out.push((&doc[start..j], &doc[vstart..vend]));
        // Resume AFTER the value, so its own bytes are never re-read as a key.
        i = vend + 1;
    }
    out
}

/// The sorted, deduped key set of `doc` — what a pin compares against a
/// revision's [`DocumentShape::keys`].
///
/// One function so the six pins cannot disagree about whether the comparison
/// is order-sensitive. It is not: a document's key ORDER is a rendering detail
/// (the same key appears once per row), while its key SET is the contract.
pub fn key_set(doc: &str) -> Vec<&str> {
    let mut keys = json_keys(doc);
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Every TOP-LEVEL entry of `doc`: its key, and the RAW slice of its value.
///
/// R2180 (open-debt item 554) — the population every plane claim in this module
/// is DERIVED from, rather than listed, for the reason that item was filed
/// about. A checker handed a written-down list of the census document's planes
/// would be a second copy of the thing it is meant to check, and a copy of that
/// list is exactly what went stale: this file's own neighbour said "the two
/// keys" over three of them for as long as the third had existed.
///
/// [`json_keys`] cannot answer this. It collects every key at every depth, so
/// `flow` and `totals` and `a_to_b` arrive beside `keyexprs` and the top level
/// is not recoverable from its output. That is not a defect there — a key-set
/// pin wants the whole tree — it is a different question, and this is the
/// function that asks it.
///
/// Deliberately not a parser, on the argument [`json_keys`] already makes: it
/// tracks nesting depth and string state and nothing else, so a value comes
/// back as the bytes between its colon and whatever ends it. A caller wanting
/// the top level of a nested object calls this again on that slice, which is
/// how a plane's own marker key is looked for at the plane's OWN depth instead
/// of anywhere inside it.
///
/// Returns empty for a document that does not open with `{`.
pub fn top_level_entries(doc: &str) -> Vec<(&str, &str)> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() && b[i] != b'{' {
        i += 1;
    }
    if i >= b.len() {
        return out;
    }
    i += 1;
    loop {
        while i < b.len() && (b[i] == b' ' || b[i] == b',' || b[i] == b'\n') {
            i += 1;
        }
        if i >= b.len() || b[i] != b'"' {
            break;
        }
        let kstart = i + 1;
        let mut j = kstart;
        while j < b.len() && b[j] != b'"' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        if j >= b.len() {
            break;
        }
        let key = &doc[kstart..j];
        i = j + 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i >= b.len() || b[i] != b':' {
            break;
        }
        i += 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let vstart = i;
        let mut depth = 0usize;
        let mut in_str = false;
        while i < b.len() {
            let c = b[i];
            if in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            match c {
                b'"' => {
                    in_str = true;
                    i += 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    i += 1;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    i += 1;
                }
                b',' if depth == 0 => break,
                _ => i += 1,
            }
        }
        if vstart >= i {
            break;
        }
        out.push((key, doc[vstart..i].trim()));
    }
    out
}

/// The planes `doc` EMITS, sorted, derived by the rule a CONSUMER applies.
///
/// R2181 (open-debt item 554's own contract, over the population its gate left
/// out). `census_json_where`'s doc fixes what a plane looks like from outside:
/// a top-level key carrying `narrowed_by_selector`. A plane a build cannot feed
/// arrives as `null` instead, which carries no marker, so both shapes are the
/// derivation — and `null` is why the declaration had to exist at all.
///
/// ONE definition, and that is the point rather than tidiness. R2180 closed item
/// 554 by making the census document carry its own plane list, and wrote this
/// derivation inline in the one test that compared the two. A second caller
/// copying those six lines would be a second copy of the plane rule, which is
/// the defect the item was filed about, one level up.
///
/// ⚠ TOP LEVEL on both sides. The marker is looked for at the plane's OWN depth
/// — `top_level_entries` applied to the value — rather than anywhere inside it.
/// A scan that does not bound the depth it counts at answers with a plane's
/// CHILDREN, and that failure is measured rather than hypothetical: a probe
/// written for this item on 2026-08-29 counted 26 planes where there are five,
/// by not bounding its scope, and the item's own filing says not to quote that
/// number for anything. `a_plane_is_a_marker_or_a_null_at_the_top_level_and_nothing_else`
/// is the arm that holds the bound here, and it is the only one a depth-blind
/// rewrite of this function fails.
///
/// Returns empty for a document with no plane, which is most of them — the
/// answer `DocumentShape::planes` gives as `&[]` and, until R2181, the half of
/// that claim nothing checked.
pub fn emitted_planes(doc: &str) -> Vec<&str> {
    let mut planes: Vec<&str> = top_level_entries(doc)
        .into_iter()
        .filter(|(_, value)| {
            *value == "null"
                || top_level_entries(value)
                    .iter()
                    .any(|(inner, _)| *inner == "narrowed_by_selector")
        })
        .map(|(key, _)| key)
        .collect();
    planes.sort_unstable();
    planes
}

/// Every JSON OBJECT in `doc`, each as its OWN `(key, raw value)` entries.
///
/// R2184 (open-debt item 556) — the THIRD walker, and the reason it is a third
/// rather than a widening of either sibling is the question it answers.
/// [`json_keys`] flattens every depth into one list, so a key's neighbours are
/// unrecoverable from it; [`top_level_entries`] recovers exactly one object's
/// own entries and stops, so an array of rows yields only its first element.
/// What "which keys accompany this value" needs is every object's OWN key set,
/// wherever that object sits.
///
/// ONE opinion about what an object entry is: each scope is parsed by
/// [`top_level_entries`] applied at the `{` that opens it, which is the same
/// move [`emitted_planes`] makes to look inside a plane. This function's own
/// work is only FINDING the openings — a linear scan that tracks string state
/// so a brace inside a string never opens a scope.
///
/// Outermost first, in order of appearance, duplicates kept: two rows with the
/// same shape are two observations, and collapsing them here would decide a
/// question the caller has not asked yet.
pub fn object_scopes(doc: &str) -> Vec<Vec<(&str, &str)>> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => out.push(top_level_entries(&doc[i..])),
            _ => {}
        }
        i += 1;
    }
    out
}

/// For `key`, ONE ENTRY PER OCCURRENCE: the word it carried there, and the
/// keys that occurrence's own object carried beside it.
///
/// R2184 (open-debt item 556) — the derivation behind [`CarriesShape`], and the
/// axis neither [`DocumentShape::keys`] nor [`ValueFamily::values`] can express.
/// A consumer that switches on a value goes on to read the keys that value
/// arrived with, and until this axis existed it read them off today's
/// rendering: `fields[].kind == "opaque"` arrives with NO `value`, and
/// `payload_decode.state` spreads eight words over six different companion
/// sets.
///
/// ⚠ PER OCCURRENCE, NOT UNIONED PER WORD, and the difference is the whole
/// classification. MEASURED on 2026-08-29 while this item was being derived: a
/// union per word reports `fields[].direction == "a"` carrying `packet` AND
/// `message_at` — a shape NO ROW OF THAT DOCUMENT HAS, because `a` occurs once
/// in a datagram row and once in a stream row. Classifying from that is
/// classifying from a set the document never emitted, and what it destroys is
/// exactly the observation that decides the question: whether one word ever
/// arrives in two different shapes.
///
/// The choice is load-bearing rather than tidy. PROBED: making this function
/// union per word turns `census.offset_space` from a passenger into a
/// discriminant and reds
/// `the_declared_carries_axis_is_the_one_the_emitters_render`. `fields`
/// survives that particular mutation because its gate renders four separate
/// documents and keeps their answers apart, which is a second reason the
/// caller groups and this function only observes.
///
/// Each occurrence's companion list is sorted and deduped, so two observations
/// of one shape compare equal. The entries themselves keep document order.
///
/// Only a STRING value counts as a word, on [`json_string_values`]' rule — a
/// number, an object or a `null` is not something a `switch` reads.
pub fn companions<'a>(doc: &'a str, key: &str) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for scope in object_scopes(doc) {
        let Some((_, raw)) = scope.iter().find(|(k, _)| *k == key) else {
            continue;
        };
        let bytes = raw.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
            continue;
        }
        let word = &raw[1..raw.len() - 1];
        let mut beside: Vec<&str> = scope
            .iter()
            .map(|(k, _)| *k)
            .filter(|k| *k != key)
            .collect();
        beside.sort_unstable();
        beside.dedup();
        out.push((word, beside));
    }
    out
}

/// Check a revision history for the rules that make a rename expressible and a
/// silent break impossible.
///
/// Takes the rows as a PARAMETER rather than reading [`DOCUMENT_HISTORY`]
/// directly, and that is what gives the rules a population: over the real table
/// every rule holds by construction, so a checker that could only be run
/// against it would be a guard nobody had ever seen fire. The tests drive it
/// with the histories a future round will actually write — an announced
/// removal, a silent one, a skipped revision.
pub fn audit(rows: &[DocumentShape]) -> Result<(), String> {
    let mut names: Vec<&str> = rows.iter().map(|r| r.document).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let doc: Vec<&DocumentShape> = rows.iter().filter(|r| r.document == name).collect();
        let mut ordered = doc.clone();
        ordered.sort_by_key(|r| r.revision);
        // A history that does not start at 1 leaves a consumer unable to tell
        // "revision 3 is the first there ever was" from "I am missing two".
        if ordered[0].revision != 1 {
            return Err(alloc::format!(
                "{name}: the first revision is {}, and a document's history starts at 1",
                ordered[0].revision
            ));
        }
        for (i, row) in ordered.iter().enumerate() {
            if row.revision != (i + 1) as u32 {
                return Err(alloc::format!(
                    "{name}: revision {} follows revision {}; revisions rise by one so a \
                     consumer can tell a shape it has not seen from one it has",
                    row.revision,
                    ordered[i.saturating_sub(1)].revision
                ));
            }
            let mut sorted: Vec<&str> = row.keys.to_vec();
            sorted.sort_unstable();
            if sorted != row.keys {
                return Err(alloc::format!(
                    "{name} r{}: the key set is not sorted, so comparing two revisions \
                     would depend on the order someone typed them in",
                    row.revision
                ));
            }
            let mut deduped = sorted.clone();
            deduped.dedup();
            if deduped.len() != sorted.len() {
                return Err(alloc::format!(
                    "{name} r{}: the key set repeats a key",
                    row.revision
                ));
            }
            // A document with no envelope is exactly the state item 509
            // measured, so a revision whose key set does not contain the
            // envelope's own keys is a revision describing a document a
            // consumer cannot read the revision off.
            for envelope in ENVELOPE_KEYS {
                if !row.keys.contains(envelope) {
                    return Err(alloc::format!(
                        "{name} r{}: the key set is missing the envelope key \
                         {envelope:?}, so this revision describes a document that \
                         does not say which revision it is",
                        row.revision
                    ));
                }
            }
            for going in row.retiring {
                if !row.keys.contains(going) {
                    return Err(alloc::format!(
                        "{name} r{}: {going:?} is announced for retirement but this \
                         revision does not emit it",
                        row.revision
                    ));
                }
            }
            // R2180 (open-debt item 554) — THE PLANES.
            //
            // Three rules, and every one is a rule the key set and the families
            // already carry, applied to the third list. Note what is NOT here:
            // no `retiring` for planes either. A plane that goes away takes its
            // KEY with it, so the announcement it needs is the one the key set
            // already demands; a key that stops being a plane while staying a
            // key would be a different change, and this table has never seen
            // one.
            let mut planes: Vec<&str> = row.planes.to_vec();
            let unsorted = planes.clone();
            planes.sort_unstable();
            if planes != unsorted {
                return Err(alloc::format!(
                    "{name} r{}: the planes are not sorted, so comparing two \
                     revisions would depend on typing order",
                    row.revision
                ));
            }
            planes.dedup();
            if planes.len() != row.planes.len() {
                return Err(alloc::format!(
                    "{name} r{}: the plane list repeats a key",
                    row.revision
                ));
            }
            for plane in row.planes {
                // The same rule item 550 paid for, and the families carry one
                // sentence up: a plane named over a key this revision does not
                // emit is proof the list was never checked against a document.
                if !row.keys.contains(plane) {
                    return Err(alloc::format!(
                        "{name} r{}: {plane:?} is declared a plane, which this \
                         revision does not emit",
                        row.revision
                    ));
                }
            }
            // A revision that declares planes EMITS them, because
            // `envelope_into` writes the list under `planes`. A key set without
            // that name describes a document a consumer cannot read the plane
            // list off, which is the state item 554 was filed about.
            if !row.planes.is_empty() && !row.keys.contains(&"planes") {
                return Err(alloc::format!(
                    "{name} r{}: planes are declared but the key set is missing \
                     \"planes\", so this revision describes a document that does \
                     not carry the list the envelope writes into it",
                    row.revision
                ));
            }
            // R2175 (open-debt item 552) — THE VALUE FAMILIES.
            //
            // Three rules, and each is the value-side twin of one the key set
            // already has. Note what is NOT here: no `retiring` for values. See
            // `ValueFamily`'s doc for the asymmetry — a value that ARRIVES is
            // the break, and the revision this row carries IS its notice.
            let mut family_keys: Vec<&str> = row.families.iter().map(|f| f.key).collect();
            let unsorted = family_keys.clone();
            family_keys.sort_unstable();
            if family_keys != unsorted {
                return Err(alloc::format!(
                    "{name} r{}: the families are not sorted by key",
                    row.revision
                ));
            }
            family_keys.dedup();
            if family_keys.len() != row.families.len() {
                return Err(alloc::format!(
                    "{name} r{}: two families claim one key; a key has one \
                     vocabulary or none",
                    row.revision
                ));
            }
            for family in row.families {
                // The rule item 550 paid for, one document over: an entry for
                // something that cannot occur is proof the list was never
                // checked. A family under a key this revision does not emit
                // pins a vocabulary no consumer can ever read.
                if !row.keys.contains(&family.key) {
                    return Err(alloc::format!(
                        "{name} r{}: a value family is declared for {:?}, which this \
                         revision does not emit",
                        row.revision,
                        family.key
                    ));
                }
                // A family with no values is the population-of-zero failure in
                // its smallest form: it would report green about a key whose
                // vocabulary nobody had written down.
                if family.values.is_empty() {
                    return Err(alloc::format!(
                        "{name} r{}: the family for {:?} declares no values, so it \
                         asserts nothing about the key it names",
                        row.revision,
                        family.key
                    ));
                }
                let mut sorted: Vec<&str> = family.values.to_vec();
                sorted.sort_unstable();
                if sorted != family.values {
                    return Err(alloc::format!(
                        "{name} r{}: the vocabulary for {:?} is not sorted, so \
                         comparing two revisions would depend on typing order",
                        row.revision,
                        family.key
                    ));
                }
                let mut deduped = sorted.clone();
                deduped.dedup();
                if deduped.len() != sorted.len() {
                    return Err(alloc::format!(
                        "{name} r{}: the vocabulary for {:?} repeats a value",
                        row.revision,
                        family.key
                    ));
                }
            }

            // R2184 (open-debt item 556) — THE CARRIES AXIS.
            //
            // Five rules. The FIRST is the one that keeps this from becoming
            // the unmeasured default R2181 had just finished closing on
            // `planes`: at the NEWEST revision of a document, every family it
            // declares has a row here. An older revision may carry `&[]`,
            // because "this revision did not declare the axis" is true of it;
            // the newest may not, because that is what the library emits today.
            let mut carried: Vec<&str> = row.carries.iter().map(|c| c.key).collect();
            let unsorted = carried.clone();
            carried.sort_unstable();
            if carried != unsorted {
                return Err(alloc::format!(
                    "{name} r{}: the carries rows are not sorted by key",
                    row.revision
                ));
            }
            carried.dedup();
            if carried.len() != row.carries.len() {
                return Err(alloc::format!(
                    "{name} r{}: two carries rows claim one key; a key decides \
                     the shape beside it or it does not",
                    row.revision
                ));
            }
            for entry in row.carries {
                let Some(family) = row.families.iter().find(|f| f.key == entry.key) else {
                    return Err(alloc::format!(
                        "{name} r{}: a carries row is declared for {:?}, which this \
                         revision declares no family for; an entry for something \
                         that cannot occur is proof the list was never checked",
                        row.revision,
                        entry.key
                    ));
                };
                let CarriesShape::Discriminant(words) = &entry.shape else {
                    continue;
                };
                let listed: Vec<&str> = words.iter().map(|w| w.word).collect();
                if listed != family.values.to_vec() {
                    return Err(alloc::format!(
                        "{name} r{}: the carries rows for {:?} name {listed:?} and the \
                         family declares {:?}. Every word gets a row, sorted the way \
                         the vocabulary is: a word with no row is one a consumer \
                         switches on with no answer, and a row with no word describes \
                         something that cannot arrive",
                        row.revision,
                        entry.key,
                        family.values
                    ));
                }
                for word in *words {
                    // A word with NO shape is one nothing was measured about;
                    // a word whose object carries nothing else is one EMPTY
                    // shape, which is `fields[].kind == "opaque"`.
                    if word.shapes.is_empty() {
                        return Err(alloc::format!(
                            "{name} r{}: {:?} = {:?} declares no shape at all, so it \
                             asserts nothing about the object it names",
                            row.revision,
                            entry.key,
                            word.word
                        ));
                    }
                    let mut seen: Vec<&[&str]> = Vec::new();
                    for shape in word.shapes {
                        let mut sorted: Vec<&str> = shape.to_vec();
                        sorted.sort_unstable();
                        if sorted != *shape {
                            return Err(alloc::format!(
                                "{name} r{}: a shape of {:?} = {:?} is not sorted, so \
                                 comparing two revisions would depend on typing order",
                                row.revision,
                                entry.key,
                                word.word
                            ));
                        }
                        let mut deduped = sorted.clone();
                        deduped.dedup();
                        if deduped.len() != sorted.len() {
                            return Err(alloc::format!(
                                "{name} r{}: a shape of {:?} = {:?} repeats a key",
                                row.revision,
                                entry.key,
                                word.word
                            ));
                        }
                        if seen.contains(shape) {
                            return Err(alloc::format!(
                                "{name} r{}: {:?} = {:?} lists one shape twice",
                                row.revision,
                                entry.key,
                                word.word
                            ));
                        }
                        seen.push(shape);
                    }
                }
                // A DISCRIMINANT WHOSE WORDS DECIDE NO KEY IS A PASSENGER,
                // mis-declared. Without this the axis rots into "every family
                // is a discriminant carrying one list", which says exactly what
                // the key set already said and would let the derivation gate
                // pass over a claim with no content. Computed by
                // [`decides_a_key`], the SAME predicate the derivation uses, so
                // the table and the emitters cannot be judged by two rules.
                if !decides_a_key(words) {
                    return Err(alloc::format!(
                        "{name} r{}: {:?} is declared a discriminant and no key is \
                         decided by the word — none that one word always brings and \
                         another never does. That is what `Passenger` says",
                        row.revision,
                        entry.key
                    ));
                }
            }
        }
        for row in &ordered {
            if row.revision != ordered[ordered.len() - 1].revision {
                continue;
            }
            let declared: Vec<&str> = row.families.iter().map(|f| f.key).collect();
            let carried: Vec<&str> = row.carries.iter().map(|c| c.key).collect();
            if declared != carried {
                return Err(alloc::format!(
                    "{name} r{} is the newest revision and declares families {declared:?} \
                     against carries rows {carried:?}. Every family the library emits \
                     today says whether its word decides the keys beside it; a family \
                     with no row is the unmeasured default this axis was added to \
                     abolish",
                    row.revision
                ));
            }
        }
        // THE RULE ITEM 509 EXISTS FOR: a key may only leave after the
        // revision before it said so. That is what turns a rename into
        // "emit both, then drop one" and a removal into an announcement.
        for pair in ordered.windows(2) {
            let (before, after) = (pair[0], pair[1]);
            for key in before.keys {
                if !after.keys.contains(key) && !before.retiring.contains(key) {
                    return Err(alloc::format!(
                        "{name} r{} drops {key:?}, which r{} did not announce in \
                         `retiring`; a consumer reading by name breaks on that, so \
                         emit both keys for one revision and drop it in the next",
                        after.revision,
                        before.revision
                    ));
                }
            }
            // R2146 (unregistered open-debt item 534) — AND THE PROMISE BINDS.
            //
            // The rule above is one-directional: it refuses a key that LEAVES
            // unannounced, and says nothing about a key ANNOUNCED and then kept.
            // So `retiring` could promise a departure that never came, and
            // nothing would notice -- a promise nobody measures is decoration,
            // not a contract. Item 534 is that half. R2123 dropped
            // `first_packet` on the schedule `retiring`'s own doc states and
            // wrote in its comment that nothing would have refused a revision
            // keeping it; this is what would have.
            //
            // CANCELLATION IS STILL POSSIBLE, and deliberately so. Keeping a key
            // is the SAFE direction for a consumer -- someone who read the
            // announcement and prepared for the departure is not broken by its
            // absence -- so a rule that forced every announcement to completion
            // would compel a pointless removal. The way to cancel is to edit the
            // announcing row's `retiring` in the same commit that adds the
            // successor: the promise and its withdrawal then land together,
            // which is a visible act rather than a silent lapse. What is refused
            // is the third thing: a successor that neither honours the promise
            // nor withdraws it.
            //
            // An announcement in the NEWEST revision has no successor yet and is
            // in flight, which is legal and unbounded here on purpose: no rule
            // over this table can force the next revision to be written. That
            // residue is named rather than gated, and
            // `every_announcement_in_the_shipped_history_is_accounted_for`
            // prints the in-flight ones by name so they cannot go quiet.
            for going in before.retiring {
                if after.keys.contains(going) {
                    return Err(alloc::format!(
                        "{name} r{} announced {going:?} as retiring and r{} still \
                         emits it; an announcement the next revision does not keep \
                         is decoration. Drop the key in r{}, or withdraw the \
                         announcement from r{} in the commit that adds r{}",
                        before.revision,
                        after.revision,
                        after.revision,
                        before.revision,
                        after.revision
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Every synthetic row carries the envelope's own three keys, because a
    // revision that does not is refused on its own rule — see
    // `a_revision_describes_a_document_that_says_which_revision_it_is`.
    const A: &[&str] = &["alpha", "beta", "document", "name", "revision"];
    const A_RENAMED: &[&str] = &["alpha", "beta", "document", "gamma", "name", "revision"];
    const A_DROPPED: &[&str] = &["alpha", "document", "gamma", "name", "revision"];

    fn row(
        revision: u32,
        keys: &'static [&'static str],
        retiring: &'static [&'static str],
    ) -> DocumentShape {
        with_families(revision, keys, retiring, &[])
    }

    /// R2175 (open-debt item 552) — a row carrying value families, so the
    /// family rules have a population that is not [`DOCUMENT_HISTORY`]. Same
    /// argument [`audit`]'s own doc makes: over the real table every rule holds
    /// by construction, and a checker only ever run against it is a guard
    /// nobody has seen fire.
    fn with_families(
        revision: u32,
        keys: &'static [&'static str],
        retiring: &'static [&'static str],
        families: &'static [ValueFamily],
    ) -> DocumentShape {
        with_planes(revision, keys, retiring, families, &[])
    }

    /// R2184 (open-debt item 556) — a row carrying the CARRIES axis, for the
    /// reason `with_planes` gives one axis over.
    fn with_carries(
        revision: u32,
        keys: &'static [&'static str],
        families: &'static [ValueFamily],
        carries: &'static [KeyCarries],
    ) -> DocumentShape {
        DocumentShape {
            document: "d",
            revision,
            keys,
            retiring: &[],
            families,
            planes: &[],
            carries,
        }
    }

    /// R2180 (open-debt item 554) — a row carrying PLANES, for the reason
    /// `with_families` gives one axis over: the real table satisfies the plane
    /// rules by construction, so a checker only ever run against it would be a
    /// guard nobody had seen fire.
    fn with_planes(
        revision: u32,
        keys: &'static [&'static str],
        retiring: &'static [&'static str],
        families: &'static [ValueFamily],
        planes: &'static [&'static str],
    ) -> DocumentShape {
        DocumentShape {
            document: "d",
            revision,
            keys,
            retiring,
            families,
            planes,
            carries: &[],
        }
    }

    /// R2119 (open-debt item 455) — a retirement IN FLIGHT is announced where
    /// the announcement does something.
    ///
    /// # Why this test exists at all
    ///
    /// [`audit`] enforces the rule at the moment a key LEAVES: a name absent
    /// from a row and from the previous row's `retiring` is an error. It says
    /// nothing while the key is still being emitted, which is the entire span
    /// during which the announcement is the only thing a consumer has.
    ///
    /// MEASURED: emptying the census row's `retiring` while this test did not
    /// exist changed no verdict anywhere — the announcement was decorative for
    /// exactly as long as it mattered. A line nothing reads is a line the next
    /// round deletes, and then the notice a consumer was promised was never
    /// given.
    ///
    /// R2123 (open-debt item 453) — AND THE DANCE COMPLETED, which is the half
    /// R2119 could not assert because it had not happened yet.
    ///
    /// This test was written to pin the IN-FLIGHT state and to be deleted with
    /// the key. Deleting it outright would have thrown away the only record
    /// that the notice was ever given, so what it asserts moved rather than
    /// went: revision 2 announced `first_packet` and emitted it beside its
    /// successor, and revision 3 -- this one -- does not emit it at all.
    ///
    /// Both halves, because either alone is satisfiable by an accident. A
    /// document that never emitted the key would pass "it is gone"; a
    /// document that never dropped it would pass "it was announced".
    ///
    /// NOT the general rule. "An announced key must actually leave in the next
    /// revision" is what [`audit`] still does not enforce, and it is open-debt
    /// item 534; this asserts one completed rename, not that the machinery
    /// makes completion happen.
    #[test]
    fn the_retired_census_key_was_announced_and_then_actually_left() {
        let rows: Vec<&DocumentShape> = DOCUMENT_HISTORY
            .iter()
            .filter(|row| row.document == CENSUS)
            .collect();
        let announced = rows
            .iter()
            .find(|row| row.retiring.contains(&"first_packet"))
            .expect(
                "census revision 2 announced `first_packet`; without that row a \
                 consumer was never given notice and the drop below is a break",
            );
        assert!(
            announced.keys.contains(&"first_packet"),
            "the revision that announced the retirement must still emit the key, \
             or the notice and the removal were the same event"
        );
        assert!(
            announced.keys.contains(&"first_anchor"),
            "and the successor beside it, because a retirement with nothing to \
             move to is a removal wearing a notice"
        );

        let newest = newest(CENSUS).expect("the census document has a revision");
        assert!(
            newest.revision > announced.revision,
            "the announcement is only kept by a LATER revision existing"
        );
        assert!(
            !newest.keys.contains(&"first_packet"),
            "revision {} still emits `first_packet`, which revision {} said was \
             going away in the next revision",
            newest.revision,
            announced.revision
        );
        assert!(
            newest.keys.contains(&"first_anchor"),
            "and the successor outlives it"
        );
    }

    /// The real table obeys its own rules.
    #[test]
    fn the_shipped_history_passes_its_own_audit() {
        audit(DOCUMENT_HISTORY).expect("the shipped document history");
    }

    /// R2181 — THE DERIVATION, DRIVEN BY DOCUMENTS THIS TREE DOES NOT EMIT.
    ///
    /// [`emitted_planes`] runs over the real documents in two crates, and over
    /// every one of them today it answers either the census plane set or
    /// nothing. That makes the LIVE population a check of the tree and no check
    /// of the rule: the shapes that would break it — a plane in a document that
    /// declares none, a marker nested where a plane's own `selection` object
    /// puts it — do not occur, so nothing there says what the function would do
    /// if they did. Synthetic documents are how the rule gets a population, the
    /// same argument [`audit`] makes about taking its rows as a parameter.
    ///
    /// Both polarities, and the CONTROL is the third case rather than an
    /// afterthought: a checker that answered "plane" to everything would pass
    /// the first two arms and is refused only by the arm that must stay silent.
    #[test]
    fn a_plane_is_a_marker_or_a_null_at_the_top_level_and_nothing_else() {
        // Positive: the two shapes a plane arrives in.
        assert_eq!(
            emitted_planes("{\"a\":{\"narrowed_by_selector\":false,\"rows\":[]},\"b\":null}"),
            vec!["a", "b"],
            "a marker-carrying object and a null are both planes"
        );

        // Negative: an ordinary key is not one, whatever it carries.
        assert!(
            emitted_planes("{\"document\":{\"name\":\"x\",\"revision\":1},\"n\":3}").is_empty(),
            "a document with no plane derives none"
        );

        // CONTROL: the marker one level too deep. A plane's `selection` object
        // carries the same word, and a depth-blind scan reported the plane's
        // CHILDREN as planes -- measured on 2026-08-29, 26 where there are 5.
        assert!(
            emitted_planes("{\"totals\":{\"flow\":{\"narrowed_by_selector\":true}}}").is_empty(),
            "a marker below a plane's own depth does not make its parent's \
             children planes"
        );

        // And sorted, so a comparison against a declaration cannot depend on
        // the order the document happens to render.
        assert_eq!(
            emitted_planes("{\"z\":null,\"a\":null}"),
            vec!["a", "z"],
            "the derivation sorts"
        );
    }

    /// R2146 (unregistered open-debt item 534) — AN ANNOUNCEMENT THE NEXT
    /// REVISION KEEPS IS REFUSED, AND CANCELLING IT IS NOT.
    ///
    /// Three shapes, because the rule has three outcomes and a test that drove
    /// only the failing one would not show that the other two remain writable:
    /// the promise KEPT (the successor drops the key), the promise BROKEN (the
    /// successor keeps it), and the promise WITHDRAWN (the announcement is
    /// edited away in the same commit that adds the successor).
    #[test]
    fn an_announcement_the_next_revision_keeps_is_refused() {
        // KEPT — the rename dance, which is what `retiring` is for.
        audit(&[row(1, A, &["beta"]), row(2, A_DROPPED, &[])])
            .expect("a promise the successor honours is the whole point");

        // BROKEN — announced, and the successor still emits it.
        let err = audit(&[row(1, A, &["beta"]), row(2, A_RENAMED, &[])])
            .expect_err("an announcement the successor keeps is decoration");
        assert!(
            err.contains("\"beta\"") && err.contains("still"),
            "the refusal must name the key and say what went wrong: {err}"
        );

        // WITHDRAWN — the announcing row no longer announces, so the successor
        // keeping the key is an ordinary revision. This is the escape the rule
        // deliberately leaves open; without it, every announcement would compel
        // a removal a consumer never needed.
        audit(&[row(1, A, &[]), row(2, A_RENAMED, &[])])
            .expect("withdrawing the announcement is a legal way out");
    }

    /// R2146 (open-debt item 534) — every announcement the SHIPPED table has
    /// ever made, and what became of it.
    ///
    /// The population is DERIVED from `DOCUMENT_HISTORY` rather than listed, and
    /// an empty one fails: a rule about announcements that has no announcement
    /// to judge is measuring nothing, and would pass forever.
    ///
    /// In-flight announcements are printed BY NAME. `audit` cannot bound how
    /// long one lives — no rule over this table can force the next revision to
    /// be written — so the residue item 534 names is made visible here instead
    /// of being left silent.
    #[test]
    fn every_announcement_in_the_shipped_history_is_accounted_for() {
        let mut honoured: vec::Vec<alloc::string::String> = vec::Vec::new();
        let mut in_flight: vec::Vec<alloc::string::String> = vec::Vec::new();

        for row in DOCUMENT_HISTORY {
            for going in row.retiring {
                let successor = DOCUMENT_HISTORY
                    .iter()
                    .find(|r| r.document == row.document && r.revision == row.revision + 1);
                match successor {
                    // `audit` already refuses a successor that keeps the key, so
                    // reaching here means the promise was kept.
                    Some(_) => honoured.push(alloc::format!(
                        "{} r{} -> {going:?} gone by r{}",
                        row.document,
                        row.revision,
                        row.revision + 1
                    )),
                    None => in_flight.push(alloc::format!(
                        "{} r{} -> {going:?} (no successor revision yet)",
                        row.document,
                        row.revision
                    )),
                }
            }
        }

        assert!(
            !(honoured.is_empty() && in_flight.is_empty()),
            "no revision in DOCUMENT_HISTORY announces a retirement, so this test \
             and the rule it guards are judging an empty set. If the table \
             genuinely carries no announcement any more, that is news: say so in \
             the round that removed the last one."
        );

        for line in &honoured {
            std::eprintln!("doc-revision announcement HONOURED: {line}");
        }
        for line in &in_flight {
            std::eprintln!("doc-revision announcement IN FLIGHT: {line}");
        }
    }

    /// Every door this library exports names a document here, and every
    /// document here is reachable.
    ///
    /// The pairing is the point: a document with no envelope is item 509's
    /// original state, and an envelope for a document nothing emits is a
    /// revision nobody can read.
    #[test]
    fn every_document_name_resolves_to_a_revision() {
        // R2114 (open-debt item 237) — the expected revision is a PAIR now,
        // and it has to be: the first document to move past 1 would otherwise
        // have had to weaken this to "some revision", which is the assertion
        // that stops noticing. `readable_surfaces` is at 2 because it grew the
        // described-format type list.
        for (name, expected) in [
            // R2119 (open-debt item 455) — the census moved to 2 when
            // `first_packet`'s retirement was announced; R2123 (item 453) to 3
            // when that key actually left and `anchor_intervals` arrived.
            // R2175 (item 552) — to 4 for a reason no earlier revision had: it
            // declares five VALUE FAMILIES and changes no key.
            // R2180 (item 554) — to 5 for a reason no earlier revision had
            // either: it declares which of its top-level keys are PLANES, and
            // the envelope carries that list, so a consumer reads it off the
            // document instead of inferring it from a `null`.
            // R2184 (item 556) — to 6 for the THIRD axis: which of its
            // families' words decide the keys that arrive beside them. All
            // five are passengers, which is a measured verdict about
            // straight-line row emitters and not a shrug.
            (CENSUS, 6u32),
            // R2175 (open-debt item 552) — the field document moved to 2 when
            // its PAYLOAD PLANE joined the pin (fifteen keys revision 1 had
            // never covered) and its first three value families were declared.
            // R2182 (item 555) — to 3 when `fields[].kind`, the field tree's
            // own discriminant, gained the sixth family. No key moved: `kind`
            // had been pinned since revision 1 and the eight words inside it
            // were declared by nothing.
            // R2184 (item 556) — to 4 for the carries axis, which found THREE
            // discriminants where the item that filed it had measured two:
            // `offset_space` decides its shape through two row emitters rather
            // than through two arms of one `match`.
            (FIELDS, 4),
            // R2121 (open-debt item 460) — the summary moved to 2 when it
            // gained `inert_counters`; R2122 (item 238) to 3 when its
            // `framing` group stopped disagreeing with the capture report's.
            (SUMMARY, 3),
            // R2175 (open-debt item 552) — to 3 when it gained
            // `value_families`, the catalogue of every switchable key's words.
            // R2184 (item 556) — to 4 when the `value_families` rows gained
            // `carries` and the `word` / `keys` under it, which is where the
            // third axis reaches a consumer at runtime.
            (READABLE_SURFACES, 4),
            (SELECTOR_DIAGNOSE, 1),
            (DECLARATIONS_DIAGNOSE, 1),
        ] {
            assert_eq!(revision(name), Some(expected), "{name}");
            // R2180 (open-debt item 554) — the envelope is asserted in BOTH
            // shapes, because it now has two. A document that declares no plane
            // renders exactly what it always did; one that declares planes adds
            // the list, and asserting only the first shape would have made the
            // new key impossible to add rather than checked.
            let planes = newest(name).expect("a document with a revision").planes;
            let head = alloc::format!("\"document\":{{\"name\":\"{name}\",\"revision\":{expected}");
            if planes.is_empty() {
                assert_eq!(envelope(name), alloc::format!("{head}}}"), "{name}");
            } else {
                let mut want = head;
                want.push_str(",\"planes\":[");
                for (i, plane) in planes.iter().enumerate() {
                    if i > 0 {
                        want.push(',');
                    }
                    let _ = write!(want, "\"{plane}\"");
                }
                want.push_str("]}");
                assert_eq!(envelope(name), want, "{name}");
            }
        }
        // A name this library does not emit renders revision 0, which the
        // audit refuses — so a typo is loud rather than a document that
        // quietly claims a shape.
        assert_eq!(revision("no-such-document"), None);
        assert!(envelope("no-such-document").contains("\"revision\":0"));
    }

    /// THE RULE: a key cannot leave unannounced, and CAN leave once announced.
    ///
    /// Both directions in one test, because a checker that refused every
    /// removal would pass the first assertion and make the rename dance
    /// impossible — which is the failure that would leave item 509 open while
    /// looking closed.
    #[test]
    fn a_key_leaves_only_after_the_revision_before_it_said_so() {
        // The dance, done right: r2 emits both names and announces the old
        // one, r3 drops it.
        let danced = vec![
            row(1, A, &[]),
            row(2, A_RENAMED, &["beta"]),
            row(3, A_DROPPED, &[]),
        ];
        audit(&danced).expect("an announced retirement is the supported path");

        // The same removal with no announcement.
        let silent = vec![
            row(1, A, &[]),
            row(2, A_RENAMED, &[]),
            row(3, A_DROPPED, &[]),
        ];
        let err = audit(&silent).expect_err("a silent removal is the break item 509 named");
        assert!(err.contains("did not announce"), "{err}");
        assert!(err.contains("\"beta\""), "{err}");
    }

    /// A history that skips a number, and one that does not start at 1.
    #[test]
    fn revisions_start_at_one_and_rise_by_one() {
        let skipped = vec![row(1, A, &[]), row(3, A, &[])];
        let err = audit(&skipped).expect_err("a skipped revision");
        assert!(err.contains("rise by one"), "{err}");

        let late = vec![row(2, A, &[])];
        let err = audit(&late).expect_err("a history that does not start at 1");
        assert!(err.contains("starts at 1"), "{err}");
    }

    /// An announcement has to be about a key the document actually emits.
    #[test]
    fn a_retirement_names_a_key_this_revision_emits() {
        let phantom: Vec<DocumentShape> = vec![row(1, A, &["delta"])];
        let err = audit(&phantom).expect_err("announcing a key that is not emitted");
        assert!(err.contains("does not emit it"), "{err}");
    }

    /// A revision describes a document that SAYS which revision it is.
    ///
    /// The rule looks circular and is not: it is what stops a round from
    /// declaring a revision for a document whose emitter never grew an
    /// envelope — which is item 509's original state, recorded in the table as
    /// though it had been fixed.
    #[test]
    fn a_revision_describes_a_document_that_says_which_revision_it_is() {
        const NO_ENVELOPE: &[&str] = &["alpha", "beta"];
        let err = audit(&[row(1, NO_ENVELOPE, &[])]).expect_err("a document with no envelope");
        assert!(err.contains("missing the envelope key"), "{err}");
    }

    /// The key sets are sorted and deduped, so two revisions can be compared
    /// at all.
    #[test]
    fn a_key_set_is_sorted_and_deduped() {
        const UNSORTED: &[&str] = &["document", "name", "revision", "beta", "alpha"];
        const REPEATED: &[&str] = &["alpha", "alpha", "document", "name", "revision"];
        let err = audit(&[row(1, UNSORTED, &[])]).expect_err("an unsorted key set");
        assert!(err.contains("not sorted"), "{err}");
        let err = audit(&[row(1, REPEATED, &[])]).expect_err("a repeated key");
        assert!(err.contains("repeats a key"), "{err}");
    }

    /// R2180 (open-debt item 554) — THE PLANE RULES, driven over histories the
    /// shipped table does not contain.
    ///
    /// [`audit`]'s own doc gives the reason this is written as four synthetic
    /// rows rather than as a pass over [`DOCUMENT_HISTORY`]: the real table
    /// satisfies every rule by construction, so a checker only ever run against
    /// it is a guard nobody has seen fire. Each arm here is a history a future
    /// round could plausibly write.
    #[test]
    fn a_plane_is_declared_over_a_key_this_revision_emits_and_carries_the_list() {
        const WITH_PLANES: &[&str] = &["alpha", "beta", "document", "name", "planes", "revision"];

        // A plane named over a key the revision does not emit — the rule item
        // 550 paid for, applied to the third list.
        let err = audit(&[with_planes(1, WITH_PLANES, &[], &[], &["gamma"])])
            .expect_err("a plane over an absent key");
        assert!(err.contains("is declared a plane"), "{err}");

        // Unsorted, so two revisions cannot be compared without knowing the
        // order someone typed them in.
        let err = audit(&[with_planes(1, WITH_PLANES, &[], &[], &["beta", "alpha"])])
            .expect_err("unsorted planes");
        assert!(err.contains("planes are not sorted"), "{err}");

        // Repeated.
        let err = audit(&[with_planes(1, WITH_PLANES, &[], &[], &["alpha", "alpha"])])
            .expect_err("a repeated plane");
        assert!(err.contains("plane list repeats"), "{err}");

        // Declared but not carried: the envelope writes the list under
        // `planes`, so a revision whose key set lacks that name describes a
        // document a consumer cannot read the list off — which is the state
        // item 554 was filed about, reached from the other side.
        const NO_LIST: &[&str] = &["alpha", "beta", "document", "name", "revision"];
        let err = audit(&[with_planes(1, NO_LIST, &[], &[], &["alpha"])])
            .expect_err("planes declared and not carried");
        assert!(err.contains("missing \"planes\""), "{err}");

        // And the control: the same rows with the plane declared over an
        // emitted key, sorted, unique and carried, pass. Without this arm every
        // assertion above would be satisfied by an `audit` that refused
        // everything.
        audit(&[with_planes(1, WITH_PLANES, &[], &[], &["alpha", "beta"])])
            .expect("a well-formed plane declaration");
    }

    /// R2184 (open-debt item 556) — THE CARRIES RULES, driven over histories
    /// the shipped table does not contain.
    ///
    /// [`audit`]'s own doc gives the reason, and it applies to this axis with
    /// more force than to the two before it: the shipped table was written
    /// against these rules, so every one of them holds there by construction.
    /// Each arm below is a history a future round could plausibly write.
    ///
    /// ⚠ THE CONTROL GROUP IS NAMED. Every arm here varies exactly one thing
    /// against the passing row at the end — the shape, the sort, the coverage,
    /// the key — and holds the rest FIXED: the document name, the key set, the
    /// vocabulary, the revision number and the family list. The 2026-08-29
    /// measurement that made this paragraph necessary is that five probe arms
    /// all missed for one reason, and the reason was in what they had held
    /// fixed rather than in what they varied.
    #[test]
    fn a_carries_row_names_a_family_and_a_discriminant_says_something() {
        const KEYS: &[&str] = &["document", "kind", "name", "revision"];
        const WORDS: &[&str] = &["one", "two"];
        const FAMILIES: &[ValueFamily] = &[ValueFamily {
            key: "kind",
            values: WORDS,
        }];
        const SPLIT: &[WordCarries] = &[
            WordCarries {
                word: "one",
                shapes: &[&["a"]],
            },
            WordCarries {
                word: "two",
                shapes: &[&["b"]],
            },
        ];

        // A row for a key this revision declares no family for — the rule item
        // 550 paid for, applied to the fourth list.
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "name",
                shape: CarriesShape::Passenger,
            }],
        )])
        .expect_err("a carries row over a key with no family");
        assert!(err.contains("declares no family for"), "{err}");

        // A DISCRIMINANT WHOSE WORDS ALL BRING THE SAME KEYS is a passenger,
        // and this is the arm that keeps the axis from rotting into "every
        // family is a discriminant carrying one list", which restates the key
        // set and asserts nothing.
        const FLAT: &[WordCarries] = &[
            WordCarries {
                word: "one",
                shapes: &[&["a"]],
            },
            WordCarries {
                word: "two",
                shapes: &[&["a"]],
            },
        ];
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(FLAT),
            }],
        )])
        .expect_err("a discriminant that discriminates nothing");
        assert!(err.contains("no key is decided by the word"), "{err}");

        // A word missing its row: the consumer switching on it has no answer.
        const SHORT: &[WordCarries] = &[WordCarries {
            word: "one",
            shapes: &[&["a"]],
        }];
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(SHORT),
            }],
        )])
        .expect_err("a word with no carries row");
        assert!(err.contains("Every word gets a row"), "{err}");

        // Unsorted companion keys, so two revisions could not be compared
        // without knowing the order someone typed them in.
        const UNSORTED: &[WordCarries] = &[
            WordCarries {
                word: "one",
                shapes: &[&["b", "a"]],
            },
            WordCarries {
                word: "two",
                shapes: &[&["b"]],
            },
        ];
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(UNSORTED),
            }],
        )])
        .expect_err("unsorted companion keys");
        assert!(err.contains("is not sorted"), "{err}");

        // A word with NO shape at all, which is not the same as a word whose
        // object carries nothing beside it — that one is a single EMPTY shape,
        // and it is `fields[].kind == "opaque"`.
        const SHAPELESS: &[WordCarries] = &[
            WordCarries {
                word: "one",
                shapes: &[],
            },
            WordCarries {
                word: "two",
                shapes: &[&["b"]],
            },
        ];
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(SHAPELESS),
            }],
        )])
        .expect_err("a word with no shape");
        assert!(err.contains("declares no shape at all"), "{err}");

        // THE ASYMMETRY `decides_a_key` rests on, driven from the declaration
        // side: `one` SOMETIMES brings `a` and `two` never does. Nothing is
        // decided by the word — a consumer told "a comes with one" would be
        // wrong half the time — so this is a passenger however much the two
        // lists differ. A rule comparing unions, or comparing intersections,
        // passes this row.
        const SOMETIMES: &[WordCarries] = &[
            WordCarries {
                word: "one",
                shapes: &[&["a"], &[]],
            },
            WordCarries {
                word: "two",
                shapes: &[&[]],
            },
        ];
        let err = audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(SOMETIMES),
            }],
        )])
        .expect_err("a word that only sometimes brings its key");
        assert!(err.contains("no key is decided by the word"), "{err}");

        // THE RULE THIS AXIS EXISTS FOR: the newest revision of a document that
        // declares a family declares its carries row too. Without it the axis
        // is the unmeasured default R2181 had just finished closing on planes.
        let err = audit(&[with_carries(1, KEYS, FAMILIES, &[])])
            .expect_err("a newest revision with a family and no carries row");
        assert!(err.contains("is the newest revision"), "{err}");

        // And an OLDER revision may carry none, which is the other half of the
        // same rule: "this revision did not declare the axis" is true of it.
        audit(&[
            with_carries(1, KEYS, FAMILIES, &[]),
            with_carries(
                2,
                KEYS,
                FAMILIES,
                &[KeyCarries {
                    key: "kind",
                    shape: CarriesShape::Discriminant(SPLIT),
                }],
            ),
        ])
        .expect("an older revision that had not made the judgement");

        // The control: one row, the family declared, the words split across two
        // shapes, sorted. Without it every assertion above would be satisfied
        // by an `audit` that refused everything.
        audit(&[with_carries(
            1,
            KEYS,
            FAMILIES,
            &[KeyCarries {
                key: "kind",
                shape: CarriesShape::Discriminant(SPLIT),
            }],
        )])
        .expect("a well-formed carries declaration");
    }
}

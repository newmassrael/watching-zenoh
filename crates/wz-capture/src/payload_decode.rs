// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y856 — APPLYING a payload declaration to one walked message: find the
//! key expression and the payload it was published under, pick the rule that
//! covers it, decode, and rebase the spans.
//!
//! ## Why this is here and not in the command line
//!
//! Every piece of it was in `wz-analyze` and reachable only by running a
//! terminal. The C ABI — the surface a product LINKS — had
//! [`crate::payload::formats::FormatMap`] in its dependency graph, no decoder
//! to put in one, and no code that would consult it if it had. That is the
//! `analysis_surface_parity.py` OPEN DEBT this round pays, and the shape of the
//! payment is R311y851's: the implementation moves beside the type, and neither
//! consumer owns it.
//!
//! ## What stays in the command line
//!
//! The RENDERING. [`crate::payload_decode::PayloadDecoding`] is the answer; how
//! it is spelled for a
//! person reading a terminal, and which flag a reader should go fix, are
//! properties of that surface and stay there.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use wz_session_core::dissect::{Field, FieldValue};
use wz_session_core::passive::Direction;

use crate::agg::KeyexprSpaces;
use crate::payload::formats::{Declaration, DeclarationId, FormatMap, PayloadField, PayloadFormat};
use crate::payload::Encoding;

/// R311y726 — THE DECLARATIONS IN FORCE FOR ONE RUN, and which of them applied.
///
/// # Why this is not on the map
///
/// R311y725 answered "which declarations bound nothing" by putting a
/// `Cell<bool>` beside every rule inside [`FormatMap`]. It worked and it put
/// the wrong fact in the wrong place: a `FormatMap` is what the reader
/// DECLARED, which does not change while a capture is walked, and "was this
/// rule ever selected" is a fact about ONE walk. Merged, the two mean a map
/// cannot be consulted twice as if it were fresh, and two analyses sharing
/// declarations would read each other's marks.
///
/// So the map went back to being configuration and this type owns the run. It
/// borrows the map, forwards the two questions the field layer asks, and
/// remembers the handle each answer came back with. `RefCell` and not `&mut`
/// because the field layer's rendering path is threaded with shared borrows
/// several calls deep — a `&mut` would have to be carried through every row
/// renderer, and the row renderers have nothing to do with this.
pub struct Declarations<'a> {
    map: &'a FormatMap<'a>,
    used: RefCell<BTreeSet<DeclarationId>>,
    /// R311y875 — the rules that bound the WRONG thing, tallied by the triple
    /// that identifies one misbinding. See [`Self::misbindings`].
    misbound: RefCell<alloc::collections::BTreeMap<MisbindingKey, usize>>,
    /// Round 2031 (item 300) — THE THIRD FINDING: a decoder that was actually
    /// applied and then REFUSED the bytes, tallied by the pair that identifies
    /// one refusal plus what the publisher had said.
    ///
    /// `misbound` above answers the two cases where one side is caught out by
    /// the other. This answers the case where the decode itself failed, which
    /// went out per message and reached no plane at all — in the listing a
    /// reader bounds precisely because it is that long. See [`Self::refusals`].
    refused: RefCell<alloc::collections::BTreeMap<RefusalKey, (usize, String)>>,
    /// Round 2026 (item 289) — WHAT THE SECOND SCAN COST: how many payloads
    /// [`crate::payload::inspect`] re-walked, and how many bytes it walked.
    ///
    /// R311y874 made the veto rest on the bytes rather than on the label, which
    /// is right and is not free: every sample whose declared encoding
    /// contradicts its rule is read a SECOND time. That is precisely the
    /// traffic a reader may have a lot of — one wrong rule on a busy topic is
    /// every sample on it — and until this round nothing said how much work it
    /// was.
    ///
    /// A COUNT and not a cap. The scan is bounded by the payload's own length,
    /// which the message bounds and the capture's limits bound above that, so
    /// the second pass is a constant factor on work already being done rather
    /// than an open-ended cost. Inventing a ceiling here would bound something
    /// that is already bounded and would make the veto's honesty depend on a
    /// number nobody chose.
    rescans: RefCell<(usize, usize)>,
    /// Round 2029 (item 298) — messages a listing CAP kept this run from
    /// walking at all.
    ///
    /// The misbinding verdict is reached during the walk, so a message the cap
    /// held back is a message no rule was ever applied to. The SET of
    /// misbindings stays complete over the range that WAS walked; the per-key
    /// sample counts become a floor, and until this round no row said so.
    ///
    /// ⚠ It is the counts that go soft, not the findings. A rule bound to the
    /// wrong thing on a busy topic shows up in the first few samples, so the
    /// list is the durable half — which is exactly why quietly truncating the
    /// numbers beside it was the dangerous shape rather than a harmless one.
    unwalked: RefCell<usize>,
}

/// R311y875 — what one misbinding IS, as a key: the topic, the rule's decoder,
/// the publisher's label, and which of the two is wrong.
///
/// A tuple and not a struct because it is a `BTreeMap` key and nothing else;
/// [`Misbinding`] is the value a reader is handed.
type MisbindingKey = (String, String, String, Misbound);

/// Round 2031 (item 300) — what one REFUSAL is, as a key: the topic, the rule's
/// decoder, and what the publisher had said about the bytes.
///
/// The decoder's own reason is deliberately NOT in the key. It is unbounded
/// text off a scanner — "unexpected byte at offset 17" and the same failure at
/// offset 43 are one thing to go look at — and keying on it would make a busy
/// topic render one row per sample, which is the very shape this plane exists
/// to collapse. One reason rides along as an EXAMPLE instead.
type RefusalKey = (String, String, RefusedUnder);

impl<'a> Declarations<'a> {
    /// A fresh ledger over `map`, with nothing applied yet.
    pub fn new(map: &'a FormatMap<'a>) -> Self {
        Self {
            map,
            used: RefCell::new(BTreeSet::new()),
            misbound: RefCell::new(alloc::collections::BTreeMap::new()),
            refused: RefCell::new(alloc::collections::BTreeMap::new()),
            rescans: RefCell::new((0, 0)),
            unwalked: RefCell::new(0),
        }
    }

    /// Round 2029 (item 298) — record that a listing cap held one message back,
    /// so no rule was applied to it.
    ///
    /// Called by the WALKER rather than by this module: the cap lives in the
    /// listing and this type cannot see it. That is the coupling item 298
    /// named — two surfaces each emitting their own `omitted` with nothing
    /// joining them — and this is the join.
    pub fn note_unwalked(&self) {
        *self.unwalked.borrow_mut() += 1;
    }

    /// How many messages a cap kept this run from walking.
    pub fn unwalked(&self) -> usize {
        *self.unwalked.borrow()
    }

    /// Round 2029 (item 298) — whether [`Self::misbindings`]'s SAMPLE COUNTS
    /// are the whole answer rather than a floor.
    ///
    /// `false` when a cap held any message back. Named for the same question
    /// [`crate::interest::Coverage::unclaimed_exact`] and
    /// [`crate::agg::KeyexprRow::anchors_exact`] answer, and deliberately the
    /// same word: a reader who has learned what `_exact` means on one plane
    /// should not have to learn it again here.
    pub fn counts_are_exact(&self) -> bool {
        self.unwalked() == 0
    }

    /// Round 2026 (item 289) — how many payloads the claim check re-walked, and
    /// over how many bytes.
    ///
    /// Read it beside [`Self::misbindings`]: a capture with one wrong rule on a
    /// busy topic pays this on every sample of that topic, and the two numbers
    /// together are what says whether a slow run is the mapping's fault.
    pub fn rescans(&self) -> (usize, usize) {
        *self.rescans.borrow()
    }

    /// Record one second scan. Called by [`judge_claim`] at the one place that
    /// performs one.
    fn note_rescan(&self, bytes: usize) {
        let mut at = self.rescans.borrow_mut();
        at.0 += 1;
        at.1 += bytes;
    }

    /// Whether any rule was installed — the map's own question, forwarded so a
    /// caller holding this type does not have to reach past it.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Whether any field NAME was declared, forwarded for the same reason.
    pub fn has_names(&self) -> bool {
        self.map.has_names()
    }

    /// The format for this keyexpr, RECORDING that the rule applied.
    pub fn for_keyexpr(&self, keyexpr: &str) -> Option<&'a dyn PayloadFormat> {
        let (id, format) = self.map.for_keyexpr(keyexpr)?;
        self.used.borrow_mut().insert(id);
        Some(format)
    }

    /// The declared name for this path, RECORDING that the declaration applied.
    pub fn field_name(&self, keyexpr: &str, path: &str) -> Option<String> {
        let (id, name) = self.map.field_name(keyexpr, path)?;
        self.used.borrow_mut().insert(id);
        Some(name.to_string())
    }

    /// The declarations this run never applied.
    ///
    /// Answerable only after a walk, and that is a property of the question
    /// rather than a caveat: before one, nothing has applied and the honest
    /// answer is "all of them".
    pub fn unused(&self) -> Vec<Declaration> {
        let used = self.used.borrow();
        self.map
            .declarations()
            .into_iter()
            .filter(|d| !used.contains(&d.id))
            .collect()
    }

    /// R311y875 — one sample whose rule and whose label disagreed, TALLIED.
    ///
    /// Called from [`decode_payload`] at the moment the disagreement is decided,
    /// which is the only place holding all four halves of the key at once. On
    /// this type and not beside the render for the reason [`Self::unused`] is
    /// here: what a run MET is a fact about the run, and a `FormatMap` is
    /// configuration that does not change while a capture is walked.
    fn record_misbinding(&self, keyexpr: &str, format: &str, declared: &str, wrong: Misbound) {
        *self
            .misbound
            .borrow_mut()
            .entry((
                String::from(keyexpr),
                String::from(format),
                String::from(declared),
                wrong,
            ))
            .or_insert(0) += 1;
    }

    /// Round 2031 (item 300) — one sample a decoder was APPLIED to and refused,
    /// TALLIED.
    ///
    /// Called from [`decode_payload`] at the decoder's own `Err` arm, which is
    /// the only place holding the topic, the rule and the claim the decode ran
    /// under at once. The first reason seen for a key is kept as the example:
    /// deterministic, cheap, and honest about being ONE sample's reason rather
    /// than a summary of them all.
    fn record_refusal(&self, keyexpr: &str, format: &str, under: RefusedUnder, why: &str) {
        let mut refused = self.refused.borrow_mut();
        let row = refused
            .entry((String::from(keyexpr), String::from(format), under))
            .or_insert_with(|| (0, String::from(why)));
        row.0 += 1;
    }

    /// Round 2031 (item 300) — THE RULES THAT WERE APPLIED AND REFUSED, which
    /// is the third question this plane can be asked and the last one it could
    /// not answer.
    ///
    /// # The silence this ends
    ///
    /// [`Self::misbindings`] ended it for the two findings where one side is
    /// caught out by the other, and stopped exactly there. The decode that ran
    /// and failed still went out ONE MESSAGE AT A TIME: a capture whose rule
    /// cannot read a topic said so once per row, in a listing a reader bounds
    /// with `--max-messages` because it is that long. Two of the three findings
    /// reached a plane and the third did not, and the asymmetry was itself
    /// invisible — a reader shown "the publisher is mislabelling" was never
    /// told the rule had not read the bytes either.
    ///
    /// # Why the unit is (topic, rule, claim) and not the sample
    ///
    /// A reader's remedy is per topic and rule: every sample on `demo/a` that a
    /// `protobuf` rule refuses is ONE thing to go look at. The claim it ran
    /// under belongs in the key rather than beside it because it is what
    /// decides WHERE to look — see [`RefusedUnder`] — and two samples on one
    /// topic can genuinely differ in it, one publisher labelling and another
    /// not.
    ///
    /// # What bounds this answer, stated rather than hidden
    ///
    /// The same bound [`Self::misbindings`] carries and for the same reason:
    /// the verdict is reached during the walk, so a caller that bounded the
    /// listing bounded this too. [`Self::counts_are_exact`] covers both tallies
    /// — it is a property of the walk, not of either finding.
    ///
    /// Most samples first, ties broken on the key, so the order is total and
    /// two runs over one capture render identically.
    pub fn refusals(&self) -> Vec<Refusal> {
        let mut found: Vec<Refusal> = self
            .refused
            .borrow()
            .iter()
            .map(|((keyexpr, format, under), (samples, example))| Refusal {
                keyexpr: keyexpr.clone(),
                format: format.clone(),
                under: *under,
                samples: *samples,
                example: example.clone(),
            })
            .collect();
        found.sort_by(|a, b| {
            b.samples
                .cmp(&a.samples)
                .then_with(|| a.keyexpr.cmp(&b.keyexpr))
                .then_with(|| a.format.cmp(&b.format))
                .then_with(|| a.under.cmp(&b.under))
        });
        found
    }

    /// R311y875 — THE RULES THAT BOUND THE WRONG THING, which is the question
    /// [`Self::unused`] is the other half of.
    ///
    /// # The silence this ends
    ///
    /// R311y873 taught the field layer to weigh a publisher's declaration
    /// against the rule covering it, and R311y874 taught it to weigh that
    /// declaration against the bytes. Both findings then went out ONE MESSAGE AT
    /// A TIME and reached no plane at all: a capture in which a rule is wrong for
    /// ten thousand samples said so ten thousand times, in a listing a reader
    /// bounds with `--max-messages` precisely because it is that long, and
    /// nothing anywhere said "this mapping is wrong" or "this topic's publisher
    /// is mislabelling". On a product whose whole output is findings, a finding
    /// that only exists per-row is a finding a reader has to already suspect.
    ///
    /// `unused` answers the rule that bound NOTHING — the pattern missed. This
    /// answers the rule that bound the wrong thing — the pattern HIT and the
    /// traffic under it says the mapping and the wire disagree. The two failures
    /// send a reader to opposite places, which is why they are separate
    /// questions rather than one list of "bad rules".
    ///
    /// # The unit is the triple, not the sample
    ///
    /// A reader's remedy is per (topic, rule, label): every sample on `demo/a`
    /// declaring `application/json` under a `protobuf` rule is ONE thing to go
    /// fix, and ten thousand rows of it is the same one thing said ten thousand
    /// times. The count rides along because the difference between one
    /// mislabelled sample and every sample on a topic is the difference between
    /// a stray publisher and a broken deployment.
    ///
    /// # What bounds this answer, stated rather than hidden
    ///
    /// The tally counts the messages a listing WALKED. A caller that bounded the
    /// listing bounded this too, because the disagreement is decided during the
    /// walk and a message that was not walked was not judged. Both surfaces
    /// report that bound beside this — the command line as its `... N more not
    /// listed` note, the C ABI as each flow's `omitted` — so the undercount is
    /// legible rather than silent. The SET is complete for what was walked; the
    /// counts are lower bounds when a bound bit.
    ///
    /// Most samples first, so the topic with the most traffic behind it is the
    /// row a reader reads first. Ties break on the triple itself, so the order
    /// is total and two runs over one capture render identically.
    pub fn misbindings(&self) -> Vec<Misbinding> {
        let mut found: Vec<Misbinding> = self
            .misbound
            .borrow()
            .iter()
            .map(|((keyexpr, format, declared, wrong), samples)| Misbinding {
                keyexpr: keyexpr.clone(),
                format: format.clone(),
                declared: declared.clone(),
                wrong: *wrong,
                samples: *samples,
            })
            .collect();
        found.sort_by(|a, b| {
            b.samples
                .cmp(&a.samples)
                .then_with(|| a.keyexpr.cmp(&b.keyexpr))
                .then_with(|| a.declared.cmp(&b.declared))
                .then_with(|| a.wrong.cmp(&b.wrong))
        });
        found
    }
}

/// Round 2031 (item 300) — WHAT THE PUBLISHER HAD SAID when a decoder that was
/// actually applied then refused the bytes.
///
/// # Why this is a separate vocabulary from [`Misbound`]
///
/// `Misbound` answers "which side is wrong", and a refusal is the case where
/// NEITHER side is caught out by the other: the rule was applied, so it was not
/// vetoed, and the label did not lose either. What failed is the decode, and the
/// remedy is somewhere else again — the capture, or the publisher's actual
/// bytes. Folding a third word into `Misbound` would make a consumer branching
/// on "which side to go fix" receive a row where the answer is "neither".
///
/// # Why three words and not one
///
/// The three send a reader to three different places, which is this plane's own
/// standing argument for splitting a finding rather than merging it:
///
/// - [`Self::Corroborated`] — the operator's rule and the publisher's label
///   name the same encoding and the bytes are still not it. Both claims agree
///   and the WIRE is the odd one out; this is the arm where a reader's capture
///   is genuinely the thing to go look at.
/// - [`Self::Unclaimed`] — nothing was declared that this reader could weigh,
///   so the rule is the only claim in the room and the traffic contradicts it.
///   The rule is the first suspect.
/// - [`Self::Refuted`] — the publisher declared something else, its own bytes
///   refuted that label, the rule was applied over it, and the rule refused
///   too. BOTH claims are now wrong about this traffic.
///
/// Counting only two of the three — which is what shipping without this type
/// did, by tallying `Refuted` as a misbinding and losing the refusal beside it
/// — hides that asymmetry: a reader sees "the publisher is mislabelling" and is
/// never told the rule did not read the bytes either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefusedUnder {
    /// The publisher named an encoding this decoder claims, and the bytes are
    /// still not that format.
    Corroborated,
    /// Nothing was declared that this reader could weigh.
    Unclaimed,
    /// The publisher named something else, its own bytes refuted that, and the
    /// rule applied over the label then refused as well.
    Refuted,
}

impl RefusedUnder {
    /// The word a consumer branches on, written ONCE.
    ///
    /// Literals rather than an index into a list — R311y926 (item 461) measured
    /// what indexing costs on the sibling vocabulary: a variant added with
    /// someone else's number compiled, shipped, and silently shared that
    /// variant's word.
    pub fn name(self) -> &'static str {
        match self {
            Self::Corroborated => "corroborated",
            Self::Unclaimed => "unclaimed",
            Self::Refuted => "refuted",
        }
    }

    /// Every word [`Self::name`] can return, WALKED rather than written down.
    ///
    /// The shape [`Misbound::names`] arrived at: a shipping caller for the
    /// chain, so an arm added later is forced at `cargo build` and not only at
    /// `cargo test`. `wz-capi-dissect` asserts its header names each of these,
    /// which is the half a compiler cannot hold.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut out = alloc::vec::Vec::new();
        let mut cur = Some(Self::Corroborated);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }

    /// The next word, so the walk above visits every arm without a list.
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Corroborated => Self::Unclaimed,
            Self::Unclaimed => Self::Refuted,
            Self::Refuted => return None,
        })
    }
}

/// R311y875 — WHICH SIDE of a misbinding is the wrong one.
///
/// Named for the thing to go fix and not for the mechanism, because that is the
/// whole value of separating them: a reader who cannot tell these apart edits
/// their command line when the deployment is broken, or files a deployment bug
/// when their own pattern is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Misbound {
    /// THE RULE. The publisher declared an encoding this decoder is not for, and
    /// its own bytes bear that declaration out — so the mapping is what is
    /// wrong, and nothing was decoded.
    Rule,
    /// THE PUBLISHER. Its declaration contradicts the rule and its OWN BYTES
    /// REFUTE THE DECLARATION, so the rule won and the sample was decoded over
    /// the label. The fields are trustworthy; the topic is mislabelled.
    Publisher,
}

impl Misbound {
    /// The word a consumer branches on, written ONCE.
    ///
    /// R311y873's rule for [`PayloadDecoding::state`], applied to this
    /// vocabulary from the round it is introduced rather than after a prose copy
    /// of it has drifted: the match is exhaustive, so a third answer added later
    /// cannot reach a consumer without choosing a word.
    /// R311y926 (item 461) — the word is written HERE rather than looked up by
    /// index in a second list. The index was a third place to get it wrong: a
    /// variant added with someone else's number compiled, shipped, and shared
    /// that variant's word, which a measurement confirmed before this changed.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Publisher => "publisher",
        }
    }

    /// Every word [`Self::name`] can return, for the consumers that document
    /// this vocabulary in prose a compiler cannot read.
    ///
    /// R311y926 (item 461) — WALKED rather than written down, and no longer
    /// `cfg(test)`. It used to be a hand-written array, which made the private
    /// `next` chain a test-only method: nothing shipping walked the variants,
    /// and a method with no production caller is dead code this workspace
    /// refuses. That put the chain's forcing at TEST-compile time, so an author
    /// who added a variant and only ran `cargo build` was the one case it did
    /// not reach.
    ///
    /// Deriving the list gives the chain a shipping caller, which moves that
    /// forcing to `cargo build`. What it does not do -- and cannot, in this
    /// language -- is make two variants sharing a word a compile error; that
    /// stays a test, and it is one the walk now guarantees will VISIT the new
    /// variant.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        Self::all().into_iter().map(Self::name).collect()
    }

    /// R311y925 (open-debt item 301) — the NEXT variant, so a caller can walk
    /// every one of them without writing the list down.
    ///
    /// # Why a chain and not an array
    ///
    /// The totality test used to open with `let all = [Rule, Publisher]`, a
    /// hand-written list. `name`'s match is exhaustive, so a third variant
    /// cannot reach a consumer unnamed — but it CAN reach one untested: leave
    /// the list alone and the new variant is simply never visited, and the
    /// duplicate-word check that is the point of the test never sees it.
    ///
    /// This match is exhaustive too, so a third variant forces an arm HERE.
    /// R311y926 (item 461) made that arm a SHIPPING requirement rather than a
    /// test one: [`Self::names`] walks the chain, so a variant with no arm
    /// fails `cargo build`. Between the two matches, a variant cannot be added
    /// and go unvisited — and the word it chooses is then checked for being its
    /// own by the totality test, which is the one claim no compiler can make.
    ///
    /// `None` from the last variant is the end of the walk, not an absence.
    ///
    /// R311y926 (item 461) — no longer `cfg(test)`. [`Self::names`] walks the
    /// chain in a shipping build, so a variant added without an arm here fails
    /// `cargo build` rather than only `cargo test`.
    fn next(self) -> Option<Self> {
        match self {
            Self::Rule => Some(Self::Publisher),
            Self::Publisher => None,
        }
    }

    /// Every variant, walked rather than listed.
    ///
    /// `Rule` is the head because it is the first arm of [`Self::name`]; the
    /// walk's ORDER is not a contract, only its completeness.
    fn all() -> alloc::vec::Vec<Self> {
        let mut out = alloc::vec::Vec::new();
        let mut cur = Some(Self::Rule);
        while let Some(v) = cur {
            out.push(v);
            cur = v.next();
        }
        out
    }
}

/// R311y875 — one topic, one rule, one label, and how many samples met them.
///
/// The value [`Declarations::misbindings`] hands back; see that method for why
/// the triple rather than the sample is the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Misbinding {
    /// The key expression the rule was matched against.
    pub keyexpr: String,
    /// The decoder the rule named.
    pub format: String,
    /// What the publisher said these payloads are.
    pub declared: String,
    /// Which side is wrong.
    pub wrong: Misbound,
    /// How many WALKED samples carried this triple. A lower bound where a
    /// listing bound bit; see [`Declarations::misbindings`].
    pub samples: usize,
}

impl Misbinding {
    /// The prose BOTH surfaces carry, written ONCE.
    ///
    /// The same rule [`crate::report::VerdictReason`] and `wz-analyze`'s
    /// `FieldNote::sentence` follow: a sentence written twice is two sentences
    /// to keep true, and this one has to be true on a terminal and inside a JSON
    /// document a program reads.
    ///
    /// Each half names the flag to go change, because a finding a reader cannot
    /// act on is a finding they will learn to skip.
    pub fn sentence(&self) -> String {
        let Self {
            keyexpr,
            format,
            declared,
            samples,
            wrong,
        } = self;
        match wrong {
            Misbound::Rule => alloc::format!(
                "MAPPING WRONG -- {samples} sample(s) on `{keyexpr}` declare `{declared}`, \
                 which the `{format}` rule is not for, and their bytes bear that out; \
                 nothing was decoded. Fix the --payload-format rule, not the wire"
            ),
            Misbound::Publisher => alloc::format!(
                "PUBLISHER MISLABELLING -- {samples} sample(s) on `{keyexpr}` declare \
                 `{declared}` and carry bytes that refute it; the `{format}` rule was \
                 applied over the label and the fields are good. Fix the publisher"
            ),
        }
    }
}

/// Round 2031 (item 300) — one rule that WAS applied and refused, as a row.
///
/// The sibling of [`Misbinding`] on the third finding. Separate rather than a
/// variant of it because the two answer different questions and send a reader
/// to different places; see [`RefusedUnder`] for why the claim it ran under is
/// part of the identity rather than a detail beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The key expression the rule was matched against.
    pub keyexpr: String,
    /// The decoder that refused.
    pub format: String,
    /// What the publisher had said about these payloads.
    pub under: RefusedUnder,
    /// How many WALKED samples refused this way. A lower bound where a listing
    /// bound bit; see [`Declarations::refusals`].
    pub samples: usize,
    /// ONE sample's reason, kept as an example rather than as a summary.
    ///
    /// The first seen for this key. A scanner's reason carries an offset, so
    /// the reasons across a topic's samples differ in ways a reader does not
    /// need and a tally must not fragment on — which is why it is here and not
    /// in the key.
    pub example: String,
}

impl Refusal {
    /// The prose BOTH surfaces carry, written ONCE — [`Misbinding::sentence`]'s
    /// rule, applied to this finding from the round it is introduced.
    ///
    /// Each arm names WHERE TO LOOK, because that is the whole value of telling
    /// the three apart.
    pub fn sentence(&self) -> String {
        let Self {
            keyexpr,
            format,
            under,
            samples,
            example,
        } = self;
        match under {
            RefusedUnder::Corroborated => alloc::format!(
                "WIRE DISAGREES WITH BOTH -- {samples} sample(s) on `{keyexpr}` declare an \
                 encoding the `{format}` rule is for, and the `{format}` decoder still \
                 refused them ({example}). Your rule and the publisher agree; look at \
                 the capture"
            ),
            RefusedUnder::Unclaimed => alloc::format!(
                "RULE REFUSED -- {samples} sample(s) on `{keyexpr}` declare nothing this \
                 reader can weigh, and the `{format}` decoder refused them ({example}). \
                 The rule is the only claim there is; check the --payload-format rule"
            ),
            RefusedUnder::Refuted => alloc::format!(
                "NEITHER CLAIM HOLDS -- {samples} sample(s) on `{keyexpr}` carry a label \
                 their own bytes refute, and the `{format}` rule applied over that label \
                 refused them too ({example}). The publisher and the rule are both wrong \
                 about this traffic"
            ),
        }
    }
}

/// Round 2031 (item 300) — the machine-readable rendering of one refusal,
/// written ONCE, for the reason [`push_misbinding`] is written once.
pub fn push_refusal(refusal: &Refusal, out: &mut String) {
    use wz_session_core::json::escape_into;
    out.push_str("{\"keyexpr\":");
    escape_into(&refusal.keyexpr, out);
    out.push_str(",\"format\":");
    escape_into(&refusal.format, out);
    out.push_str(",\"under\":\"");
    out.push_str(refusal.under.name());
    out.push_str("\",\"samples\":");
    out.push_str(&refusal.samples.to_string());
    out.push_str(",\"example\":");
    escape_into(&refusal.example, out);
    out.push_str(",\"note\":");
    escape_into(&refusal.sentence(), out);
    out.push('}');
}

/// R311y875 — the machine-readable rendering of one misbinding, written ONCE.
///
/// Both surfaces emit this array — `wz-analyze`'s `--fields --json` and the C
/// ABI's `fields_json` — and they emit it through this function for the reason
/// [`push_decoding`] exists: the field layer already carries TWO JSON emitters
/// for its rows (`debt-census-emit-two-renderings`), and a finding whose object
/// shape differed between the surface a person reads and the surface a product
/// links would be a contract that disagrees with itself.
pub fn push_misbinding(misbinding: &Misbinding, out: &mut String) {
    use wz_session_core::json::escape_into;
    out.push_str("{\"keyexpr\":");
    escape_into(&misbinding.keyexpr, out);
    out.push_str(",\"format\":");
    escape_into(&misbinding.format, out);
    out.push_str(",\"declared\":");
    escape_into(&misbinding.declared, out);
    out.push_str(",\"wrong\":\"");
    out.push_str(misbinding.wrong.name());
    out.push_str("\",\"samples\":");
    out.push_str(&misbinding.samples.to_string());
    out.push_str(",\"note\":");
    escape_into(&misbinding.sentence(), out);
    out.push('}');
}

/// R311y875 — the whole `payload_mapping` array, empty or not.
///
/// ALWAYS rendered by every caller, never omitted when empty — R311y720's
/// standing rule. A consumer that had to test for the key would read its absence
/// as "no rule is misbound", which is exactly the assumption this plane exists
/// to stop being made for free.
///
/// # Round 2031 (item 300) — and `payload_refusals` beside it, under this name
///
/// The name undersells what this emits and has since R311y875's own
/// `payload_mapping_counts_exact`, which is not a misbinding either. Stated
/// rather than quietly widened: this function renders THE PAYLOAD MAPPING
/// PLANE, and the third finding is emitted here rather than through a sibling
/// for two reasons a rename would not buy back.
///
/// The exactness flag covers BOTH tallies — it is a property of the walk, not
/// of either finding — and a consumer must not have to look beside a different
/// array to learn whether these numbers are a floor. And there are two callers,
/// `wz-analyze` and the C ABI; a second function is a second thing each of them
/// can forget, which is the shape this module refuses one doc-comment up.
pub fn push_misbindings(declarations: Option<&Declarations<'_>>, out: &mut String) {
    out.push_str("\"payload_mapping\":[");
    if let Some(declarations) = declarations {
        for (i, misbinding) in declarations.misbindings().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_misbinding(misbinding, out);
        }
    }
    out.push(']');
    // Round 2031 (item 300) — THE THIRD FINDING, which until this round existed
    // only per message. Same rule as the array above: always rendered, empty or
    // not, so an absent key can never be read as "nothing refused".
    out.push_str(",\"payload_refusals\":[");
    if let Some(declarations) = declarations {
        for (i, refusal) in declarations.refusals().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_refusal(refusal, out);
        }
    }
    out.push(']');
    // Round 2029 (item 298) — AND WHETHER THOSE SAMPLE COUNTS ARE THE WHOLE
    // ANSWER. The verdict is reached during the walk, so a listing cap
    // truncates the tally as well as the listing; both surfaces already
    // reported their own `omitted` and nothing joined the two.
    //
    // STRUCTURAL, and `true` when no ledger is present at all: with no rules
    // there are no counts, and a consumer must not have to test for the key to
    // learn whether the numbers beside it are a floor.
    let exact = declarations.is_none_or(Declarations::counts_are_exact);
    out.push_str(",\"payload_mapping_counts_exact\":");
    out.push_str(if exact { "true" } else { "false" });
}

/// R311y701 (PF2) — what a keyexpr id is resolved AGAINST.
///
/// The two halves a `WireExpr` needs and a field tree alone does not carry:
/// which side sent this message, and what that flow has declared so far.
#[derive(Clone, Copy)]
pub struct KeyexprAt<'a> {
    direction: Direction,
    spaces: &'a KeyexprSpaces,
}

impl<'a> KeyexprAt<'a> {
    /// A row travelling `direction`, resolved against `spaces`.
    ///
    /// A constructor rather than public fields, because the pair is one fact:
    /// a caller that could supply one without the other could hand over a
    /// direction with nothing to resolve against.
    pub fn new(direction: Direction, spaces: &'a KeyexprSpaces) -> Self {
        Self { direction, spaces }
    }
}

/// What became of one message's payload under the declarations in force.
///
/// # Why every non-decode is a named answer rather than silence
///
/// A rule that did not fire and a rule that fired and found nothing look
/// identical in an empty listing, and they send a reader to opposite places:
/// one is a mapping to fix, the other is traffic to look at. The keyexpr that
/// was TESTED is carried for the same reason — a reader whose rule covers
/// `demo/**` needs to see that this message's keyexpr was `other/thing` before
/// they start doubting the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadDecoding {
    /// No rules at all. Renders nothing: a reader who declared no format is not
    /// told about payloads they did not ask about.
    NoRules,
    /// This message carries no payload field. Not every zenoh message does.
    NoPayload,
    /// The keyexpr is a numeric id with no suffix on the wire, so no rule can
    /// be tested against it at all.
    ///
    /// Said rather than skipped: this is the ordinary shape of a capture that
    /// began after the declarations, and a reader whose rules silently cover
    /// nothing would blame the rules.
    KeyexprUnresolved,
    /// A keyexpr, and no rule covers it.
    NoRule(String),
    /// Decoded, and the fields with spans in the MESSAGE's coordinates.
    Decoded {
        /// The key expression the rule was matched against.
        keyexpr: String,
        /// The decoder that read it.
        format: String,
        /// The fields, rebased into the message's coordinate space.
        fields: Vec<PayloadField>,
        /// R311y874 — the encoding this sample DECLARED, when the rule was
        /// applied over that declaration rather than in agreement with it.
        ///
        /// `Some` only where the publisher's own bytes refute its own label, so
        /// the field names a deployment bug the reader is otherwise not told
        /// about on this plane: their rule was right and the topic is
        /// mislabelled. `None` is the ordinary decode.
        ///
        /// An `Option` that is always RENDERED, never omitted — R311y720's rule
        /// for `name`, which the rest of this document follows: a consumer must
        /// never have to test for a key to learn that a fact is unknown.
        ///
        /// Carries the NAME and not the reason. `Mismatch` already has two
        /// renderings (`report.rs` for text, `census_json.rs` for JSON) and a
        /// third spelling of one value is the standing drift this workspace
        /// keeps paying for; the reason belongs to the payload plane, which is
        /// where that finding is produced.
        despite_encoding: Option<String>,
    },
    /// R311y873 — the sample's OWN declared encoding contradicts the rule, so
    /// the format was never applied.
    ///
    /// Distinct from [`Self::Refused`] and that distinction is the whole
    /// finding: `Refused` says the BYTES are not this format and sends a reader
    /// to their capture, which in this case is exactly right. Here the rule is
    /// what is wrong — a publisher stated what it sent and the mapping
    /// disagreed — and a reader who cannot tell the two apart will go looking
    /// at a wire that has nothing to answer for.
    EncodingMismatch {
        /// The key expression the rule was matched against.
        keyexpr: String,
        /// The decoder the rule named.
        format: String,
        /// What the publisher said this payload is.
        declared: String,
        /// Round 2025 (item 285) — WAS THE LABEL THIS VETO RESTS ON ACTUALLY
        /// CHECKED?
        ///
        /// `true` when [`crate::payload::inspect`] looked at the bytes and
        /// they bear the declaration out, so the publisher is corroborated and
        /// the operator's rule is the thing that is wrong. `false` when
        /// `inspect` could not say — a `Shape::Binary` or unknown declaration
        /// comes back [`crate::payload::Verdict::Opaque`], nothing contradicts
        /// it, and the veto stands on a claim NOBODY MEASURED.
        ///
        /// # Why this is a field and not a second state word
        ///
        /// A `state` string is what a C consumer branches on, and a new word
        /// makes every existing branch fall through on traffic it used to
        /// handle. This ABI's contract permits ADDED KEYS, which is the same
        /// reasoning R311y919 gave for putting `offset_space` beside
        /// `first_packet` rather than renaming it.
        ///
        /// # The deployment this is about
        ///
        /// `application/cdr` — what every ROS 2 publisher declares. It is
        /// binary, so no shape check can refute it, and under a protobuf rule
        /// its traffic is hidden on the authority of a label this reader never
        /// weighed. That the answer is still to withhold the decode is a
        /// defensible default; that a reader could not tell it from a MEASURED
        /// veto was not.
        checked: bool,
    },
    /// The format was applied and refused.
    Refused {
        /// The key expression the rule was matched against.
        keyexpr: String,
        /// The decoder that refused.
        format: String,
        /// What it said.
        why: String,
    },
}

impl PayloadDecoding {
    /// R311y873 — the `state` word a consumer branches on, written ONCE.
    ///
    /// # Why the emit does not spell these itself any more
    ///
    /// It did, and this round measured what that cost. The vocabulary is
    /// enumerated by hand in three places — this enum, the C ABI's rustdoc, and
    /// `wz_dissect.h` — and adding a sixth state left BOTH prose lists saying
    /// "one of five", each naming a set that no longer existed. The strings
    /// themselves were the only part a compiler could have held, so they are
    /// held here: `push_decoding` asks, and a variant added later cannot reach
    /// the wire without a word, because this match is exhaustive.
    ///
    /// What a compiler still cannot hold is the PROSE. That is why
    /// `wz-capi-dissect` carries a test asserting the header names every word
    /// this returns — the gate for the half that is not a type.
    pub fn state(&self) -> &'static str {
        Self::STATES[match self {
            Self::NoRules => 0,
            Self::NoPayload => 1,
            Self::KeyexprUnresolved => 2,
            Self::NoRule(_) => 3,
            Self::EncodingMismatch { .. } => 4,
            Self::Refused { .. } => 5,
            Self::Decoded { .. } => 6,
        }]
    }

    /// R311y873 — EVERY `state` word, for the consumers that document the
    /// vocabulary in prose a compiler cannot read.
    ///
    /// # Why an indexed array rather than seven string literals
    ///
    /// The list has to be reachable as a SET — `wz-capi-dissect` asserts its
    /// header names each one — and a set assembled by hand beside a match is a
    /// second enumeration, which is the shape that just failed. Indexing joins
    /// them: a variant added to [`Self::state`] must choose an index, a word
    /// added here changes this array's LENGTH, and the length is written in the
    /// type. Neither half can move alone.
    ///
    /// The residue, stated rather than hidden: an author who points a new
    /// variant at an EXISTING index gets two variants sharing one word and no
    /// compiler complains. That is a narrower hole than the one it replaces,
    /// and it is a deliberate act rather than an omission.
    pub const STATES: [&'static str; 7] = [
        "no_rules",
        "no_payload",
        "keyexpr_unresolved",
        "no_rule",
        "encoding_mismatch",
        "refused",
        "decoded",
    ];

    /// R311y926 (open-debt item 283) — the NEXT variant, so a test can visit
    /// every one of them without writing the list down.
    ///
    /// # The hole this closes, which the doc above named and left open
    ///
    /// `STATES` is indexed, so a variant added to [`Self::state`] must choose
    /// an index and a new word changes the array's length, which is written in
    /// the type. What neither holds is an author who points the new variant at
    /// an EXISTING index: two variants then render one word and the compiler
    /// says nothing. That residue is the whole of item 283, and until R311y926
    /// nothing in the workspace asserted the map from variant to word is
    /// injective — `wz-capi-dissect`'s test checks the HEADER names each word,
    /// which is a different claim.
    ///
    /// # Why a chain, on an enum whose variants carry data
    ///
    /// The walk is about the DISCRIMINANT, so each arm builds the next variant
    /// with empty payloads; the data is furniture here and is not asserted on.
    /// The match is exhaustive, so an eighth variant forces an arm, and an
    /// author who ends the chain early leaves the walk shorter than `STATES` —
    /// which the test compares. Item 301 settled this shape on `Misbound` one
    /// round earlier.
    #[cfg(test)]
    fn next(&self) -> Option<Self> {
        Some(match self {
            Self::NoRules => Self::NoPayload,
            Self::NoPayload => Self::KeyexprUnresolved,
            Self::KeyexprUnresolved => Self::NoRule(String::new()),
            Self::NoRule(_) => Self::EncodingMismatch {
                keyexpr: String::new(),
                format: String::new(),
                declared: String::new(),
                checked: false,
            },
            Self::EncodingMismatch { .. } => Self::Refused {
                keyexpr: String::new(),
                format: String::new(),
                why: String::new(),
            },
            Self::Refused { .. } => Self::Decoded {
                keyexpr: String::new(),
                format: String::new(),
                fields: Vec::new(),
                despite_encoding: None,
            },
            Self::Decoded { .. } => return None,
        })
    }

    /// Every variant, walked rather than listed. The ORDER is not a contract,
    /// only the completeness.
    #[cfg(test)]
    fn all() -> Vec<Self> {
        let mut out = Vec::new();
        let mut cur = Some(Self::NoRules);
        while let Some(v) = cur {
            cur = v.next();
            out.push(v);
        }
        out
    }
}

/// The keyexpr of the `WireExpr` under `field`, RESOLVED.
///
/// # R311y701 (PF2) — why the suffix alone was not the answer
///
/// This read the `suffix` text and stopped, on the note that the id-to-path
/// table lived in another plane. Two things were wrong with that.
///
/// The first is a silence: a capture that began AFTER the declarations names
/// every keyexpr by id alone, which is the ordinary shape of a capture taken
/// from a running system. Every rule then matched nothing and the listing said
/// `keyexpr_unresolved` for each message — honest, and useless.
///
/// The second is worse and was not noticed when that note was written: a
/// message carrying BOTH an id and a suffix has the id's base PREPENDED to the
/// suffix, so reading the suffix alone reported `/temp` for a record published
/// under `demo/sensor/temp`. That is a wrong keyexpr rather than a missing one,
/// and a rule keyed on `demo/**` silently did not fire on traffic it covers.
///
/// The resolution itself is [`KeyexprSpaces::resolve_parts`], never a second
/// copy of the rule.
pub fn subtree_keyexpr(field: &Field, at: KeyexprAt<'_>) -> Option<String> {
    if field.name == "keyexpr" {
        if let FieldValue::Nested(parts) = &field.value {
            let mut id = 0u64;
            let mut mapping = 0u64;
            let mut suffix: Option<&str> = None;
            for part in parts {
                match (part.name.as_ref(), &part.value) {
                    ("id", FieldValue::Uint(v)) => id = *v,
                    ("mapping", FieldValue::Bits(v)) => mapping = *v,
                    ("suffix", FieldValue::Text(text)) => suffix = Some(text),
                    _ => {}
                }
            }
            // The `M` bit names the table: 1 is the SENDER's space, which for a
            // message travelling this way is this direction's own, and 0 is the
            // receiver's. `KeyexprSpaces::resolve` derives the same choice from
            // the codec variant; this derives it from the bit the walk records,
            // and both hand the same question to one resolver.
            let space = if mapping == 1 {
                at.direction
            } else {
                at.direction.peer()
            };
            return at
                .spaces
                .resolve_parts(space, id, suffix)
                .ok()
                .filter(|k| !k.is_empty());
        }
    }
    if let FieldValue::Nested(children) = &field.value {
        return children.iter().find_map(|c| subtree_keyexpr(c, at));
    }
    None
}

/// The payload BYTES anywhere under `field`.
///
/// Bytes and not a group: a `Frame`'s `payload` is a walked sub-structure and a
/// message's is the application's own bytes, and only the second is something a
/// format decodes.
pub fn subtree_payload_bytes(field: &Field) -> Option<&Field> {
    if field.name == "payload" && matches!(field.value, FieldValue::Bytes(_)) {
        return Some(field);
    }
    if let FieldValue::Nested(children) = &field.value {
        return children.iter().find_map(subtree_payload_bytes);
    }
    None
}

/// R311y699 — the keyexpr and the payload OF ONE MESSAGE.
///
/// # Why this is not two `find` calls
///
/// `Field::find` is first-match-by-name over the whole tree, and its own doc
/// warns that a group sharing a leaf's name SHADOWS it. Both names collide
/// here: a `Frame`'s body is a group called `payload`, so `find("payload")`
/// returns the whole batch rather than the `MsgPut`'s bytes. MEASURED — the
/// first version of this function decoded a Frame's payload group and the rule
/// never fired.
///
/// Worse than the shadowing is what two independent lookups would MEAN. A
/// batch carries several messages; taking the first keyexpr and the first
/// payload bytes anywhere under it would pair a keyexpr with a payload the
/// sender never put under it, and the rule would decode the wrong bytes while
/// naming the right topic. So the pair is found INNERMOST-FIRST inside one
/// subtree: the node returned is the smallest one holding both.
pub fn keyexpr_and_payload<'a>(field: &'a Field, at: KeyexprAt<'_>) -> Option<(String, &'a Field)> {
    message_node(field, at).map(|(_, keyexpr, payload)| (keyexpr, payload))
}

/// R311y873 — the same search, answering with the NODE it stopped at.
///
/// The innermost-first rule above is subtle and was arrived at by measurement,
/// so the encoding lookup does not get a second copy of it: this is the one
/// walk, and [`keyexpr_and_payload`] is a projection of its answer. The node is
/// what a sibling field has to be read out of — an encoding is not under the
/// payload, it is beside it — and taking the first `encoding` anywhere in the
/// whole tree would pair a batch's second message's claim with this one's
/// bytes, which is exactly the defect that doc warns about for `payload`.
fn message_node<'a>(field: &'a Field, at: KeyexprAt<'_>) -> Option<(&'a Field, String, &'a Field)> {
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            if let Some(found) = message_node(child, at) {
                return Some(found);
            }
        }
    }
    let keyexpr = subtree_keyexpr(field, at)?;
    let payload = subtree_payload_bytes(field)?;
    Some((field, keyexpr, payload))
}

/// R311y873 — the encoding ONE message declared, read off its walked group.
///
/// [`Encoding::Absent`] when the record carried no `encoding` group, which is
/// what the type already means and what the wire already means: the default,
/// `zenoh/bytes`. The packed word is handed over unshifted because
/// [`Encoding::from_packed`] owns that packing — a caller that shifted it here
/// would be a second reader of the same wire word.
fn declared_encoding(node: &Field) -> Encoding<'_> {
    fn group(field: &Field) -> Option<&Field> {
        if field.name == "encoding" && matches!(field.value, FieldValue::Nested(_)) {
            return Some(field);
        }
        if let FieldValue::Nested(children) = &field.value {
            return children.iter().find_map(group);
        }
        None
    }
    let Some(FieldValue::Nested(parts)) = group(node).map(|f| &f.value) else {
        return Encoding::Absent;
    };
    let mut packed: Option<u32> = None;
    let mut schema: Option<&str> = None;
    for part in parts {
        match (part.name.as_ref(), &part.value) {
            ("packed_id", FieldValue::Uint(v)) => packed = Some(*v as u32),
            ("schema", FieldValue::Text(text)) => schema = Some(text),
            _ => {}
        }
    }
    match packed {
        Some(packed) => Encoding::from_packed(packed, schema),
        None => Encoding::Absent,
    }
}

/// R311y874 — what one sample's DECLARATION does to the rule that covers it.
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// Nothing stands in the rule's way: the format named no encodings, the
    /// publisher named none, or the two agree.
    ///
    /// Round 2031 (item 300) — the `bool` says WHICH of those, because a
    /// refusal downstream means opposite things under them. `true` when the
    /// publisher named an encoding this decoder claims, so the operator and
    /// the publisher AGREE and only the bytes are the odd one out. `false`
    /// when nobody claimed anything this reader could weigh — the format
    /// opted out, the record carried no encoding, the id was `zenoh/bytes`,
    /// or this build cannot read the id — and then the rule is the only
    /// claim there is.
    ///
    /// Carried rather than recomputed at the refusal, which would be a second
    /// spelling of the judgement this function exists to make once. The shape
    /// is [`Self::Vetoes`]'s own: a verdict word plus the measurement it
    /// rests on.
    Agrees(bool),
    /// The declaration contradicts the rule and the rule loses. Carries the
    /// declared name and whether anything CHECKED that name.
    ///
    /// Round 2025 (item 285) — the `bool` is the correction. This variant's
    /// doc used to read "AND its own bytes bear it out, so the rule is the
    /// thing that is wrong", and that was true of only one of the two ways to
    /// get here. `inspect` corroborating a text or JSON label is a measurement;
    /// `inspect` returning `Opaque` on a binary one is silence, and the veto
    /// then rests on exactly the unchecked claim R311y874 removed from the
    /// OTHER direction. Both still veto — that is a defensible default — and
    /// they are no longer the same answer on the page.
    Vetoes(String, bool),
    /// The declaration contradicts the rule and ITS OWN BYTES REFUTE IT, so the
    /// rule wins and the reader is told whose label was overridden.
    Refuted(String),
}

#[cfg(test)]
impl Claim {
    /// Round 2027 (item 293) — WHAT THIS ARM DOES TO THE ROW, as one word.
    ///
    /// # The gate this is half of
    ///
    /// `Claim` had three arms and nothing outside `decode_payload`'s match
    /// holding them. The compiler holds EXHAUSTIVENESS — a fourth arm without
    /// a match arm does not build — and item 293 is about what it cannot hold:
    /// an author who points a new arm at an EXISTING outcome. Two claims then
    /// do one thing and nothing says so. That is item 283's finding, which
    /// `PayloadDecoding::state` already carries a walk for, arriving one enum
    /// over.
    ///
    /// ⚠ `cfg(test)`, UNLIKE `Misbound`'s walk, and the difference is worth
    /// stating rather than copying. R311y926 took that one out of `cfg(test)`
    /// because `Misbound::names` walks it in a SHIPPING build — a real
    /// consumer existed. `Claim` is internal and nothing shipping asks it what
    /// its arms are, so the same move here would mean inventing a caller to
    /// justify a gate. The first draft did it anyway and `cargo doc` refused
    /// the crate with `associated items are never used`.
    ///
    /// What is lost by the gate being test-only is stated plainly: an arm
    /// added with no entry here fails `cargo test`, not `cargo build`. The
    /// EXHAUSTIVENESS half still fails the build, because `decode_payload`'s
    /// match is not test-only — so what escapes a shipping build is only the
    /// distinctness question, which is the one this test asks.
    ///
    /// The words are what the arm CAUSES, not what it is called — `applies`,
    /// `withholds`, `overrides` — because that is the property two arms must
    /// not share. Naming them after the variants would make the distinctness
    /// test compare the variant set with itself.
    fn outcome(&self) -> &'static str {
        match self {
            Self::Agrees(_) => "applies",
            Self::Vetoes(..) => "withholds",
            Self::Refuted(_) => "overrides",
        }
    }

    /// The next arm, so a test visits every one without writing the list down.
    ///
    /// `None` from the last is the end of the walk, not an absence. The
    /// payloads are the cheapest values that construct: this chain is about
    /// which arms EXIST, and an arm's contents are the business of the tests
    /// that drive real traffic through it.
    fn next(&self) -> Option<Self> {
        Some(match self {
            Self::Agrees(_) => Self::Vetoes(String::new(), false),
            Self::Vetoes(..) => Self::Refuted(String::new()),
            Self::Refuted(_) => return None,
        })
    }

    /// Every arm, walked rather than listed.
    fn all() -> alloc::vec::Vec<Self> {
        let mut out = alloc::vec::Vec::new();
        let mut cur = Some(Self::Agrees(false));
        while let Some(v) = cur {
            cur = v.next();
            out.push(v);
        }
        out
    }
}

/// R311y873 — the publisher's claim, weighed against `format`'s rule and, since
/// R311y874, against the bytes the claim is about.
///
/// # The three answers that are not contradictions
///
/// A format that named no encodings has opted out and is applied as before. An
/// [`Encoding::Absent`] record and the default id 0 are the same fact — the
/// publisher claimed nothing — and silence must never be read as disagreement,
/// or the nanopb captures this decoder exists for would all be refused. An
/// [`Encoding::Unknown`] id is a claim this BUILD cannot read; calling it a
/// contradiction would blame a capture for a table this binary is behind on.
///
/// # R311y874 — and then the claim is CHECKED, which is the point of the rule
///
/// R311y873 stopped at "the publisher named something else" and vetoed. That
/// believed a label nobody had held against the bytes it labels, which is
/// exactly the credulity this crate's opening rule is about — pointed the other
/// way. A publisher that declares `application/json` and ships protobuf makes
/// the operator's rule RIGHT and its own label WRONG, and vetoing there hides
/// the data on the authority of a statement this reader can refute in one call.
///
/// So the veto now rests on [`crate::payload::inspect`], the same judgement the
/// payload plane publishes, rather than on a second opinion invented here.
///
/// The residue is stated rather than hidden: `inspect` can only refute a
/// declaration whose shape says something checkable — text and JSON. A binary
/// or unknown declaration comes back [`crate::payload::Verdict::Opaque`], so
/// nothing contradicts it and the veto stands. That is the honest limit of what
/// bytes can say about a label, not a gap in the check.
fn judge_claim(
    format: &dyn PayloadFormat,
    node: &Field,
    bytes: &[u8],
    // Round 2026 (item 289) — the run, so the SECOND SCAN below is counted at
    // the one place that performs one. Threaded in rather than returned,
    // because a caller that had to remember to tally is a caller that
    // eventually does not.
    run: &Declarations<'_>,
) -> Claim {
    // Round 2031 (item 300) — `false`: the format opted out of the question,
    // so no label was weighed and the rule stands unopposed.
    let Some(accepted) = format.encodings() else {
        return Claim::Agrees(false);
    };
    let declared = declared_encoding(node);
    // `false` again, and for the same reason from a reader's side: the record
    // carried no encoding, or carried an id this build's table does not have.
    let Encoding::Known { id, name, .. } = declared else {
        return Claim::Agrees(false);
    };
    // Id 0 is `zenoh/bytes`, which a publisher gets by saying nothing at all.
    // Told apart from the other table entries HERE rather than by leaving it
    // out of the table: it is a real encoding a publisher may also name
    // deliberately, and this reader cannot distinguish the two — so the
    // benefit of the doubt goes to the traffic.
    //
    // Round 2031 (item 300) — and the two halves of this condition are now
    // told apart, because they are not the same fact. `accepted.contains` is
    // a publisher CORROBORATING the rule; id 0 is a publisher saying nothing
    // and being given the benefit of the doubt. Both let the decoder run and
    // only one of them is evidence, which is exactly the distinction a
    // refusal downstream needs.
    if accepted.contains(&name) {
        return Claim::Agrees(true);
    }
    if id == 0 {
        return Claim::Agrees(false);
    }
    // Round 2026 (item 289) — THE SECOND SCAN, counted at the line that starts
    // it. Everything above this returns without re-reading the payload; from
    // here the bytes are walked again.
    run.note_rescan(bytes.len());
    match crate::payload::inspect(declared, bytes) {
        crate::payload::Verdict::NotAsDeclared { .. } => Claim::Refuted(String::from(name)),
        // Round 2025 (item 285) — `Opaque` is SILENCE, not corroboration. The
        // bytes were looked at and the shape had nothing to say about them, so
        // the veto that follows is a default rather than a finding. Told apart
        // here because this is the only place that knows.
        crate::payload::Verdict::Opaque { .. } => Claim::Vetoes(String::from(name), false),
        // `NotOnTheWire` joins it: the payload slot holds an SHM descriptor, so
        // there are no data bytes to weigh the label against at all. Reading
        // that as corroboration would be the confident wrong answer that
        // variant's own doc is written against.
        crate::payload::Verdict::NotOnTheWire { .. } => Claim::Vetoes(String::from(name), false),
        _ => Claim::Vetoes(String::from(name), true),
    }
}

/// Apply the mapping to one walked message.
pub fn decode_payload(field: &Field, map: &Declarations<'_>, at: KeyexprAt<'_>) -> PayloadDecoding {
    if map.is_empty() {
        return PayloadDecoding::NoRules;
    }
    let Some((node, keyexpr, payload)) = message_node(field, at) else {
        // Either there is no payload under any keyexpr, or the only keyexpr is
        // a numeric id. The two are told apart by asking again for each half.
        return if subtree_payload_bytes(field).is_none() {
            PayloadDecoding::NoPayload
        } else {
            PayloadDecoding::KeyexprUnresolved
        };
    };
    let FieldValue::Bytes(bytes) = &payload.value else {
        return PayloadDecoding::NoPayload;
    };
    let Some(format) = map.for_keyexpr(&keyexpr) else {
        return PayloadDecoding::NoRule(keyexpr);
    };
    // R311y873 — the sender's claim is checked BEFORE the decoder runs, which
    // is this crate's own rule (`payload.rs`'s opening) finally reaching the
    // field layer. Before the decode and not after it, because a decoder that
    // walked contradicting bytes and happened to SUCCEED is the half of the
    // defect a refusal never shows: `{"a":1}` opens a valid protobuf tag, and
    // the reader is handed fields no publisher sent.
    // R311y874 — and the claim is itself checked, so a label its own bytes
    // refute cannot hide the data behind it.
    // R311y875 — and either disagreement is TALLIED here, at the one point that
    // holds the topic, the rule and the label together. Both findings went out
    // per message until this round and reached no plane at all, so a capture
    // where a mapping is wrong for every sample on a topic said so once per row
    // — in the listing a reader bounds precisely because it is that long.
    // Round 2031 (item 300) — and the claim the decoder ends up running UNDER
    // is carried down to its `Err` arm, because a refusal means opposite things
    // under the three of them. Derived from the judgement already made rather
    // than asked again below, which would be a second spelling of it.
    let mut under = RefusedUnder::Unclaimed;
    let despite_encoding = match judge_claim(format, node, bytes, map) {
        Claim::Agrees(corroborated) => {
            if corroborated {
                under = RefusedUnder::Corroborated;
            }
            None
        }
        Claim::Vetoes(declared, checked) => {
            map.record_misbinding(&keyexpr, format.name(), &declared, Misbound::Rule);
            return PayloadDecoding::EncodingMismatch {
                keyexpr,
                format: String::from(format.name()),
                declared,
                checked,
            };
        }
        Claim::Refuted(declared) => {
            map.record_misbinding(&keyexpr, format.name(), &declared, Misbound::Publisher);
            // Round 2031 (item 300) — a refusal AFTER this is the arm where
            // both claims are wrong, and until this round the misbinding above
            // was tallied while the refusal beside it was dropped. A reader was
            // told the publisher was mislabelling and never told the rule did
            // not read the bytes either.
            under = RefusedUnder::Refuted;
            Some(declared)
        }
    };
    match format.decode(bytes) {
        Ok(mut fields) => {
            // The spans arrive PAYLOAD-relative and every other span in this
            // listing is MESSAGE-relative (R311y677). Rebasing here is the only
            // place that knows the payload's own offset, and leaving the two
            // spaces mixed in one listing is the defect R311y677 measured.
            let base = payload.span.start;
            for f in &mut fields {
                f.start += base;
                f.end += base;
                // R311y720 (PF4) — and the DECLARED name, where the deployment
                // gave one for this path under this keyexpr. Attached here
                // because this is the one place that holds both the resolved
                // keyexpr and the decoded paths; the decoder has the paths and
                // no keyexpr, and the map has neither until now.
                f.name = map.field_name(&keyexpr, &f.path);
            }
            PayloadDecoding::Decoded {
                keyexpr,
                format: format.name().to_string(),
                fields,
                despite_encoding,
            }
        }
        Err(why) => {
            let why = why.to_string();
            // Round 2031 (item 300) — TALLIED, at the one point that holds the
            // topic, the rule, and the claim the decode ran under. The finding
            // went out per message until this round and reached no plane at
            // all, which on a busy topic is one row per sample in a listing a
            // reader bounds precisely because it is that long.
            map.record_refusal(&keyexpr, format.name(), under, &why);
            PayloadDecoding::Refused {
                keyexpr,
                format: format.name().to_string(),
                why,
            }
        }
    }
}

/// R311y856 — the machine-readable rendering of one decoding, written ONCE.
///
/// # Why this is not left to each surface
///
/// It already had been. `wz-analyze` spelled these five states into JSON and
/// the C ABI had no payload block at all, so the moment the ABI grew one there
/// would have been two renderings of one value -- which is the standing
/// `debt-census-emit-two-renderings` and exactly what R311y851 refused to add a
/// third case of. The state vocabulary is a contract with a consumer that
/// branches on it; a second copy is a second contract that drifts.
///
/// The TEXT rendering stays in the command line. How a person reading a
/// terminal is told which flag to go fix is a property of that surface.
pub fn push_decoding(decoding: &PayloadDecoding, out: &mut String) {
    use wz_session_core::json::escape_into;
    // R311y873 — the word comes from `PayloadDecoding::state`, so this function
    // renders SHAPE and the vocabulary lives on the type. Opened here rather
    // than repeated in seven arms, which is how the arms and the prose lists
    // came to disagree in the first place.
    let open = |out: &mut String| {
        out.push_str("{\"state\":\"");
        out.push_str(decoding.state());
        out.push('"');
    };
    match decoding {
        // A caller is expected to skip the block entirely for this state -- a
        // reader who declared nothing is not told about payloads they did not
        // ask about. Rendered rather than unreachable so this function is total
        // over the type: an `unreachable!` here would make a caller's ordering
        // mistake a panic in a library a C consumer links.
        PayloadDecoding::NoRules | PayloadDecoding::NoPayload => {
            open(out);
            out.push('}');
        }
        PayloadDecoding::KeyexprUnresolved => {
            open(out);
            out.push('}');
        }
        PayloadDecoding::NoRule(keyexpr) => {
            open(out);
            out.push_str(",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push('}');
        }
        PayloadDecoding::EncodingMismatch {
            keyexpr,
            format,
            declared,
            checked,
        } => {
            open(out);
            out.push_str(",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push_str(",\"format\":");
            escape_into(format, out);
            out.push_str(",\"declared\":");
            escape_into(declared, out);
            // Round 2025 (item 285) — an ADDED key, which this ABI's contract
            // permits where a renamed or removed one would break a linking
            // consumer. `false` is the answer for every binary declaration,
            // `application/cdr` above all, and it says the veto rests on a
            // label nothing weighed.
            out.push_str(",\"declaration_checked\":");
            out.push_str(if *checked { "true" } else { "false" });
            out.push('}');
        }
        PayloadDecoding::Refused {
            keyexpr,
            format,
            why,
        } => {
            open(out);
            out.push_str(",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push_str(",\"format\":");
            escape_into(format, out);
            out.push_str(",\"why\":");
            escape_into(why, out);
            out.push('}');
        }
        PayloadDecoding::Decoded {
            keyexpr,
            format,
            fields,
            despite_encoding,
        } => {
            open(out);
            out.push_str(",\"keyexpr\":");
            escape_into(keyexpr, out);
            // R311y874 — present with a `null` rather than absent, R311y720's
            // rule: a consumer must never have to test for a key to learn that
            // a fact is unknown. Here the fact is "was this decoded over the
            // publisher's own label", and a missing key would read as "no",
            // which is the answer this field exists to stop being assumed.
            out.push_str(",\"despite_encoding\":");
            match despite_encoding {
                Some(declared) => escape_into(declared, out),
                None => out.push_str("null"),
            }
            out.push_str(",\"format\":");
            escape_into(format, out);
            out.push_str(",\"fields\":[");
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"path\":");
                escape_into(&f.path, out);
                // R311y720 (PF4) — `name` is present with a `null` rather than
                // absent when no declaration covers the path, on the structural
                // rule the rest of this JSON follows: a consumer must never have
                // to test for a key to learn that a fact is unknown.
                out.push_str(",\"name\":");
                match &f.name {
                    Some(name) => escape_into(name, out),
                    None => out.push_str("null"),
                }
                out.push_str(",\"value\":");
                escape_into(&f.value, out);
                out.push_str(",\"start\":");
                out.push_str(&f.start.to_string());
                out.push_str(",\"end\":");
                out.push_str(&f.end.to_string());
                out.push('}');
            }
            out.push_str("]}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::formats::FormatMap;
    use alloc::vec;

    /// A walked `MsgPut` on `demo/a` declaring `encoding_id`, carrying `bytes`.
    ///
    /// Shaped exactly as `wz_session_core::dissect::walk_msg_put` shapes one —
    /// the `encoding` group holds the PACKED word the wire carries, because
    /// `Encoding::from_packed` is the only reader of it and a test that handed
    /// it a pre-shifted id would be proving something the wire never says.
    fn put_declaring(encoding_id: u16, bytes: &[u8]) -> Field {
        use wz_session_core::dissect::Span;
        let f = |name: &'static str, value: FieldValue| Field {
            name: name.into(),
            span: Span { start: 0, end: 0 },
            value,
        };
        f(
            "msg_put",
            FieldValue::Nested(vec![
                f(
                    "keyexpr",
                    FieldValue::Nested(vec![
                        f("id", FieldValue::Uint(0)),
                        f("mapping", FieldValue::Bits(1)),
                        f("suffix", FieldValue::Text(String::from("demo/a"))),
                    ]),
                ),
                f(
                    "encoding",
                    FieldValue::Nested(vec![
                        f("packed_id", FieldValue::Uint(u64::from(encoding_id) << 1)),
                        f("has_schema", FieldValue::Flag(false)),
                        f("id", FieldValue::Bits(u64::from(encoding_id))),
                    ]),
                ),
                f("payload", FieldValue::Bytes(bytes.to_vec())),
            ]),
        )
    }

    /// The three encoding ids this test file names, by their table position in
    /// `wz_codecs::encoding_ids::ENCODING_ID_TO_STR`. Asserted rather than
    /// hard-coded blind: an upstream insertion that shifted the table would
    /// otherwise silently retarget every assertion below.
    const ENC_ZENOH_BYTES: u16 = 0;
    const ENC_TEXT_PLAIN: u16 = 4;
    const ENC_JSON: u16 = 5;
    const ENC_PROTOBUF: u16 = 13;

    #[test]
    fn the_encoding_ids_this_file_names_are_the_ones_upstream_holds() {
        use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;
        assert_eq!(ENCODING_ID_TO_STR[ENC_ZENOH_BYTES as usize], "zenoh/bytes");
        assert_eq!(ENCODING_ID_TO_STR[ENC_JSON as usize], "application/json");
        assert_eq!(
            ENCODING_ID_TO_STR[ENC_PROTOBUF as usize],
            "application/protobuf"
        );
    }

    /// R311y873 — A RULE IS NOT DECODED AGAINST A SAMPLE THAT CONTRADICTS IT.
    ///
    /// `payload.rs` opens by stating this crate's own rule — the encoding is
    /// the SENDER'S CLAIM, and a claim is checked before it is believed — and
    /// the payload PLANE checks it. The FIELD layer did not: `decode_payload`
    /// selected a format by key expression alone and applied it to whatever
    /// bytes were under one.
    ///
    /// A key expression is not the unit the claim travels in. Zenoh carries
    /// `encoding` on every sample, so one keyexpr legitimately carries two of
    /// them, and `--payload-format demo/**=protobuf` then walks a JSON body
    /// with a varint reader. What that produced is the worse half of the
    /// defect: not a refusal, but FIELDS — `{"a":1}` opens `0x7b`, a valid tag
    /// for field 15 wire type 3, and the reader is shown a structure no
    /// publisher ever sent.
    ///
    /// The verdict names the RULE, because the rule is the thing that is
    /// wrong. `Refused` would send a reader to their capture, and the capture
    /// is exactly right.
    #[test]
    fn a_sample_whose_declared_encoding_contradicts_the_rule_is_not_decoded() {
        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let run = Declarations::new(&map);
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);

        let json = put_declaring(ENC_JSON, br#"{"a":1}"#);
        assert_eq!(
            decode_payload(&json, &run, at),
            PayloadDecoding::EncodingMismatch {
                keyexpr: String::from("demo/a"),
                format: String::from("protobuf"),
                declared: String::from("application/json"),
                // Round 2025 (item 285) — CHECKED. The bytes are JSON and the
                // label says JSON, so `inspect` corroborated the publisher and
                // this veto is a measurement.
                checked: true,
            },
            "a publisher that said application/json is not decoded by a \
             protobuf rule, and the report names the rule"
        );
    }

    /// R311y909 — A JSON RULE OVER A JSON PUBLISHER DECODES ITS FIELDS.
    ///
    /// # Why this test is the round and not a corollary of the decoder's own
    ///
    /// Every mechanism on this seam was built around JSON and none of them
    /// could reach it. The test directly above is the proof: the encodings set,
    /// the claim adjudication and the misbinding tally all exist because a
    /// `protobuf` rule walked a JSON body, and the only thing a reader whose
    /// fleet publishes JSON could be told was which rule NOT to apply. A unit
    /// test of the decoder would not have shown that, because the decoder is
    /// not where the gap was — the REGISTRY was.
    #[test]
    fn a_json_rule_over_a_publisher_that_declared_json_decodes_its_fields() {
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);

        let sample = put_declaring(ENC_JSON, br#"{"temp":21.5}"#);
        match decode_payload(&sample, &run, at) {
            PayloadDecoding::Decoded {
                keyexpr,
                format,
                fields,
                despite_encoding,
            } => {
                assert_eq!(keyexpr, "demo/a");
                assert_eq!(format, "json");
                assert_eq!(
                    despite_encoding, None,
                    "the label and the bytes agree, so nothing was overridden"
                );
                let seen: Vec<(&str, &str)> = fields
                    .iter()
                    .map(|f| (f.path.as_str(), f.value.as_str()))
                    .collect();
                assert_eq!(
                    seen,
                    vec![("$", "object 1 member(s)"), ("$.temp", "number 21.5")],
                    "and the document's own member name is the path to it"
                );
            }
            other => panic!("a JSON rule over a JSON publisher must decode: {other:?}"),
        }
    }

    /// R311y909 — and the veto works in the OTHER direction now that there are
    /// two formats to point it in.
    ///
    /// Until this round the encodings check had exactly one member, so every
    /// witness for it was `protobuf` rule versus JSON label. A rule that is
    /// wrong the other way round — a `json` rule over a topic whose publisher
    /// says protobuf — had no way to be written, and a check with one direction
    /// is a check that has never been asked the general question.
    #[test]
    fn a_json_rule_over_a_protobuf_publisher_is_vetoed_and_names_the_rule() {
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);

        // field 1, varint, value 42 -- real protobuf, and not JSON at byte 0.
        let sample = put_declaring(ENC_PROTOBUF, &[0x08, 0x2a]);
        assert_eq!(
            decode_payload(&sample, &run, at),
            PayloadDecoding::EncodingMismatch {
                keyexpr: String::from("demo/a"),
                format: String::from("json"),
                declared: String::from("application/protobuf"),
                // Round 2025 (item 285) — UNCHECKED, and this leg is where the
                // item is visible without looking for it: protobuf is binary,
                // `inspect` answers `Opaque`, and the veto that follows rests
                // on a label nothing weighed. The verdict is unchanged; what it
                // now says about itself is not.
                checked: false,
            },
            "the rule is what is wrong, so the verdict names the rule"
        );
    }

    /// R311y909 — a publisher that declared NOTHING is decoded by a JSON rule,
    /// the same rule `protobuf` answers to.
    ///
    /// Id 0 is `zenoh/bytes`, which is what a publisher gets by saying nothing,
    /// and silence must never be read as disagreement. Written for `json` too
    /// because the branch is per-format only in the sense that each format's
    /// encodings set is consulted — a format whose set accidentally CONTAINED
    /// the default would silently claim every unlabelled payload in a capture.
    #[test]
    fn a_json_rule_decodes_a_publisher_that_declared_no_encoding_at_all() {
        use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);

        let sample = put_declaring(ENC_ZENOH_BYTES, br#"[1,2]"#);
        match decode_payload(&sample, &run, at) {
            PayloadDecoding::Decoded { format, fields, .. } => {
                assert_eq!(format, "json");
                assert_eq!(
                    fields.first().map(|f| f.value.as_str()),
                    Some("array 2 element(s)"),
                    "an unlabelled payload the rule covers is read: {fields:?}"
                );
            }
            other => panic!("silence is not disagreement: {other:?}"),
        }
        // And the default is not in the claimed set, which is what keeps the
        // branch above a decision about SILENCE rather than a claim about it.
        assert!(
            !crate::payload::formats::Json
                .encodings()
                .expect("json names its encodings")
                .contains(&ENCODING_ID_TO_STR[ENC_ZENOH_BYTES as usize]),
            "`zenoh/bytes` must not be a claimed encoding"
        );
    }

    /// ITEM 293 — EVERY `Claim` ARM DOES ITS OWN THING, AND REAL TRAFFIC
    /// REACHES EACH ONE.
    ///
    /// # What the compiler already holds, and what it cannot
    ///
    /// Exhaustiveness: a fourth arm without a match arm in `decode_payload`
    /// does not build. What no compiler can hold is an author pointing a new
    /// arm at an EXISTING outcome — two claims then do one thing and nothing
    /// says so. That is item 283's finding, which `PayloadDecoding::state`
    /// carries a walk for, arriving one enum over.
    ///
    /// # Two halves, and the second is the one that would have been skipped
    ///
    /// The walk asserts the outcomes are DISTINCT. On its own that is a claim
    /// about a `match` in this file agreeing with another `match` in this file,
    /// which is worth little. So the second half drives REAL TRAFFIC through
    /// `decode_payload` — one fixture per arm — and asserts the row that comes
    /// back is the one the arm's word names. An arm whose word says
    /// `withholds` and whose traffic decodes fails here.
    #[test]
    fn every_claim_arm_has_its_own_outcome_and_traffic_that_reaches_it() {
        let all = Claim::all();
        assert!(
            !all.is_empty(),
            "the walk visited no arm at all, so nothing below was measured"
        );
        let mut words: Vec<&str> = all.iter().map(Claim::outcome).collect();
        let visited = words.len();
        words.sort_unstable();
        words.dedup();
        assert_eq!(
            words.len(),
            visited,
            "two arms share an outcome word, so one of them does something \
             nothing distinguishes: {:?}",
            all.iter().map(Claim::outcome).collect::<Vec<_>>()
        );

        // THE OTHER HALF. Each arm, reached by traffic, judged by what the row
        // turns out to be — so the words above are about behaviour rather than
        // about a second `match` beside the first.
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        let json: &[u8] = br#"{"a":1}"#;
        let protobuf: &[u8] = &[0x08, 0x2a];

        let mut json_rule = FormatMap::new();
        json_rule
            .declare("demo/**=json")
            .expect("a keyexpr pattern");
        let mut pb_rule = FormatMap::new();
        pb_rule
            .declare("demo/**=protobuf")
            .expect("a keyexpr pattern");

        // `applies` — the label and the rule agree.
        let run = Declarations::new(&json_rule);
        let applies = decode_payload(&put_declaring(ENC_JSON, json), &run, at);
        // `withholds` — a label the bytes bear out, against a rule that is not
        // for it.
        let run2 = Declarations::new(&pb_rule);
        let withholds = decode_payload(&put_declaring(ENC_JSON, json), &run2, at);
        // `overrides` — a label the bytes REFUTE, so the rule wins and the row
        // says whose label was overridden.
        let run3 = Declarations::new(&pb_rule);
        let overrides = decode_payload(&put_declaring(ENC_JSON, protobuf), &run3, at);

        let word = |d: &PayloadDecoding| match d {
            PayloadDecoding::Decoded {
                despite_encoding: None,
                ..
            } => "applies",
            PayloadDecoding::Decoded {
                despite_encoding: Some(_),
                ..
            } => "overrides",
            PayloadDecoding::EncodingMismatch { .. } => "withholds",
            other => panic!("no claim arm produces this row: {other:?}"),
        };
        assert_eq!(
            (word(&applies), word(&withholds), word(&overrides)),
            ("applies", "withholds", "overrides"),
            "each arm's word must be what its traffic actually does:\n  \
             {applies:?}\n  {withholds:?}\n  {overrides:?}"
        );
        // And every word the walk holds was reached by one of those three. A
        // fourth arm added with a fourth word fails here until traffic for it
        // exists — which is the point: an unreachable answer is not an answer.
        let reached = [word(&applies), word(&withholds), word(&overrides)];
        for arm in &all {
            assert!(
                reached.contains(&arm.outcome()),
                "no traffic in this test reaches the `{}` arm, so the walk \
                 holds a word nothing produces",
                arm.outcome()
            );
        }
    }

    /// ITEM 289 — THE SECOND SCAN IS COUNTED, AND ONLY WHERE IT HAPPENS.
    ///
    /// # The item
    ///
    /// R311y874 made the veto rest on the bytes rather than on the label. That
    /// is right and it is not free: every sample whose declared encoding
    /// contradicts its rule has its payload walked a SECOND time. One wrong
    /// rule on a busy topic is every sample on that topic — the traffic a
    /// reader is likeliest to have a lot of — and nothing measured it.
    ///
    /// # What is asserted, and why not a ceiling
    ///
    /// The count and the byte total, and that both are ZERO on the paths that
    /// do not rescan. A cap is deliberately not added: the scan is bounded by
    /// the payload's own length, which the message bounds and the capture's
    /// limits bound above that, so this is a constant factor on work already
    /// being done. A ceiling here would bound something already bounded and
    /// make the veto's honesty depend on a number nobody chose.
    ///
    /// # The three no-rescan paths are the discriminator
    ///
    /// A sample the rule AGREES with, one whose publisher declared nothing, and
    /// one under a format that names no encodings. Each returns before the
    /// inspect call. Without them a counter that simply incremented per sample
    /// would pass the first leg and measure nothing.
    #[test]
    fn the_second_scan_is_counted_and_only_the_contradicting_samples_pay_it() {
        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        let body: &[u8] = br#"{"a":1}"#;

        // ONE contradicting sample: declared JSON, rule says protobuf.
        let run = Declarations::new(&map);
        assert_eq!(
            run.rescans(),
            (0, 0),
            "nothing walked before the first call"
        );
        let _ = decode_payload(&put_declaring(ENC_JSON, body), &run, at);
        assert_eq!(
            run.rescans(),
            (1, body.len()),
            "one contradicting sample is one second scan, over its own bytes"
        );
        // And it ACCUMULATES, which is the whole point on a busy topic.
        let _ = decode_payload(&put_declaring(ENC_JSON, body), &run, at);
        assert_eq!(run.rescans(), (2, body.len() * 2));

        // PATH 1 — the publisher declared nothing. Id 0 returns `Agrees`
        // before the inspect call.
        let silent = Declarations::new(&map);
        let _ = decode_payload(&put_declaring(ENC_ZENOH_BYTES, body), &silent, at);
        assert_eq!(
            silent.rescans(),
            (0, 0),
            "silence is not disagreement, so nothing is re-walked"
        );

        // PATH 2 — the rule and the label agree.
        let mut agreeing = FormatMap::new();
        agreeing.declare("demo/**=json").expect("a keyexpr pattern");
        let agreed = Declarations::new(&agreeing);
        let _ = decode_payload(&put_declaring(ENC_JSON, body), &agreed, at);
        assert_eq!(agreed.rescans(), (0, 0), "an agreeing label costs nothing");

        // PATH 3 — a format that names no encodings opts out entirely.
        let acme = Proprietary;
        let mut opted = FormatMap::new();
        opted.insert("demo/**", &acme).expect("a keyexpr pattern");
        let out = Declarations::new(&opted);
        let _ = decode_payload(&put_declaring(ENC_JSON, body), &out, at);
        assert_eq!(
            out.rescans(),
            (0, 0),
            "the opt-out returns before the claim is weighed at all"
        );
    }

    /// ITEM 285 — A BINARY LABEL VETOES A RULE ON A CLAIM NOBODY CHECKED, AND
    /// THE PAGE NOW SAYS SO.
    ///
    /// # The defect
    ///
    /// R311y874 stopped the veto resting on an unchecked claim — for the
    /// declarations `payload::inspect` can judge. Its own carry named the
    /// residue: `inspect` refutes only what a shape says something about, so
    /// text and JSON. A `Shape::Binary` or unknown declaration comes back
    /// `Verdict::Opaque`, nothing contradicts it, and the veto stands with
    /// nothing behind it.
    ///
    /// `application/cdr` is inside that set, and it is what EVERY ROS 2
    /// publisher declares. Under a protobuf rule its traffic was withheld on
    /// the authority of a label this reader never weighed — and the verdict was
    /// indistinguishable from one where the label had been corroborated.
    ///
    /// # What changed, and what deliberately did not
    ///
    /// Not the outcome: withholding the decode is still a defensible default,
    /// and reversing it would be this crate believing the OPERATOR's claim
    /// instead of the publisher's, which is the same credulity facing the other
    /// way. What changed is that the verdict now carries whether anything
    /// measured the label.
    ///
    /// # The pairing is the test
    ///
    /// Both legs are the SAME shape — a declaration the rule refuses, bytes the
    /// rule would decode — and differ only in whether the declaration is
    /// checkable. A single leg would show a `false` that could equally be a
    /// field nothing ever sets.
    #[test]
    fn a_binary_label_vetoes_unchecked_and_a_text_one_does_not() {
        // Derived from the shipped table rather than transcribed, on the rule
        // `the_encoding_ids_this_file_names_are_the_ones_upstream_holds`
        // already applies to its neighbours.
        const ENC_CDR: u16 = 7;
        assert_eq!(
            wz_codecs::encoding_ids::ENCODING_ID_TO_STR[ENC_CDR as usize],
            "application/cdr",
            "the id this leg is about must still be the one ROS 2 declares"
        );

        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        let run = Declarations::new(&map);
        // Valid protobuf, so the RULE would have decoded these bytes happily.
        // What stops it either way is the label.
        let bytes: &[u8] = &[0x08, 0x2a];

        match decode_payload(&put_declaring(ENC_CDR, bytes), &run, at) {
            PayloadDecoding::EncodingMismatch {
                ref declared,
                checked,
                ..
            } => {
                assert_eq!(declared, "application/cdr");
                assert!(
                    !checked,
                    "`application/cdr` is binary: `inspect` returns Opaque, so \
                     nothing weighed this label and the veto is a default -- \
                     THIS IS ITEM 285"
                );
            }
            other => panic!("the label still vetoes; only its warrant changed: {other:?}"),
        }

        // THE PAIR. A JSON label over JSON bytes vetoes too, and there the
        // publisher WAS corroborated.
        match decode_payload(&put_declaring(ENC_JSON, br#"{"a":1}"#), &run, at) {
            PayloadDecoding::EncodingMismatch { checked, .. } => assert!(
                checked,
                "a text-shaped label over bytes that bear it out IS measured, \
                 so `false` above is a decision and not an unset field"
            ),
            other => panic!("{other:?}"),
        }

        // AND IT REACHES THE DOCUMENT, because a fact only a Rust caller can
        // read is not what this plane ships.
        let mut out = String::new();
        push_decoding(
            &decode_payload(&put_declaring(ENC_CDR, bytes), &run, at),
            &mut out,
        );
        assert!(
            out.contains("\"declaration_checked\":false"),
            "the C consumer hiding ROS 2 traffic behind a protobuf rule must be \
             able to see the veto was never measured: {out}"
        );
    }

    /// A THIRD-PARTY FORMAT: the shape this trait is an extension point FOR.
    ///
    /// Item 280 — it does NOT override `encodings()`, which is the whole
    /// subject. Every built-in names its own, so the default arm has users
    /// (anyone implementing this trait for a proprietary format) and, until
    /// Round 2023, no witness.
    ///
    /// The decoder is deliberately trivial and self-identifying: one field
    /// whose value is the byte count. What is under test is the CLAIM
    /// arbitration, not a parser.
    struct Proprietary;

    impl crate::payload::formats::PayloadFormat for Proprietary {
        fn name(&self) -> &str {
            "acme-telemetry"
        }
        fn decode(
            &self,
            payload: &[u8],
        ) -> Result<
            alloc::vec::Vec<crate::payload::formats::PayloadField>,
            crate::payload::formats::PayloadFormatError,
        > {
            Ok(vec![crate::payload::formats::PayloadField {
                path: String::from("len"),
                // `None` as a decoder returns it, which is the invariant
                // `PayloadField::name` states: a name comes from a
                // declaration, never from a decoder.
                name: None,
                value: alloc::format!("{} byte(s)", payload.len()),
                start: 0,
                end: payload.len(),
            }])
        }
        // `encodings()` NOT overridden — see the struct doc.
    }

    /// ITEM 280 — A FORMAT THAT DECLINES TO NAME ITS ENCODINGS IS APPLIED
    /// WHATEVER THE PUBLISHER DECLARED.
    ///
    /// # The arm
    ///
    /// `judge_claim` returns `Claim::Agrees` the moment `encodings()` is
    /// `None`, before it looks at the declaration at all. That is the
    /// documented meaning — the opt-out restores the behaviour that existed
    /// before encodings were checked — and it is the arm a third-party format
    /// actually takes, because only a format that knows its own MIME names can
    /// name them.
    ///
    /// Nothing drove it. Every built-in overrides `encodings()`, so every
    /// existing test enters `judge_claim` past that line.
    ///
    /// # The three declarations, and why the third is not optional
    ///
    /// A publisher saying nothing (`zenoh/bytes`), one declaring a MIME the
    /// format has never heard of, and one declaring a MIME whose bytes ITSELF
    /// contradicts. The third is the discriminator: for a format that DOES name
    /// its encodings that case ends in `Claim::Refuted` and the rule still
    /// applies but the report says `despite_encoding`. For a format that
    /// declines, there is no claim to refute and no qualification to print —
    /// and a fix that routed the opt-out through `inspect` anyway would pass
    /// the first two legs and fail this one.
    #[test]
    fn a_format_that_names_no_encodings_is_applied_whatever_was_declared() {
        let acme = Proprietary;
        let mut map = FormatMap::new();
        map.insert("demo/**", &acme).expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        let run = Declarations::new(&map);

        // JSON bytes, so the `ENC_JSON` leg is a declaration its own bytes
        // AGREE with — the case a naive opt-out is likeliest to get wrong by
        // deferring to `inspect` and finding nothing to refute.
        let body: &[u8] = b"{\"a\":1}";

        for (what, encoding) in [
            ("said nothing", ENC_ZENOH_BYTES),
            ("declared JSON, and meant it", ENC_JSON),
        ] {
            match decode_payload(&put_declaring(encoding, body), &run, at) {
                PayloadDecoding::Decoded {
                    ref fields,
                    ref despite_encoding,
                    ..
                } => {
                    assert_eq!(
                        fields.first().map(|f| f.value.as_str()),
                        Some("7 byte(s)"),
                        "{what}: the third-party format ran: {fields:?}"
                    );
                    assert_eq!(
                        despite_encoding.as_deref(),
                        None,
                        "{what}: a format that names no encodings has no claim \
                         to be acting DESPITE -- printing one would tell the \
                         reader this decode overrode something"
                    );
                }
                other => panic!("{what}: the rule must apply: {other:?}"),
            }
        }

        // THE DISCRIMINATOR. Bytes that are NOT JSON under a `application/json`
        // label: for a format that names its encodings this is
        // `Claim::Refuted` and the report says so. Here there is no claim, so
        // the decode is unqualified — same as the two legs above, which is
        // exactly the point.
        let protobuf: &[u8] = &[0x08, 0x2a];
        match decode_payload(&put_declaring(ENC_JSON, protobuf), &run, at) {
            PayloadDecoding::Decoded {
                ref fields,
                ref despite_encoding,
                ..
            } => {
                assert_eq!(fields.first().map(|f| f.value.as_str()), Some("2 byte(s)"));
                assert_eq!(
                    despite_encoding.as_deref(),
                    None,
                    "there is no claim here to be acting despite: the format \
                     declined to name encodings, so nothing was contradicted"
                );
            }
            other => panic!("the rule must apply here too: {other:?}"),
        }

        // THE CONTROL, and the reason this test is not just describing itself:
        // a format that DOES name its encodings reports the same declaration
        // differently. Without this leg, `despite_encoding == None` above could
        // mean the field is never populated by anything.
        //
        // ⚠ The pairing is the REFUTED one and not any mismatch. A format that
        // names its encodings meeting a declaration it does not accept has two
        // outcomes: `Claim::Refuted` when `inspect` can prove the label false —
        // which decodes, qualified — and `Claim::Vetoes` when it cannot, which
        // returns `EncodingMismatch` and decodes nothing. The first draft of
        // this control picked the second (JSON bytes labelled protobuf, which
        // `inspect` cannot refute because protobuf is opaque) and failed for a
        // reason that had nothing to do with item 280.
        let mut named = FormatMap::new();
        named
            .declare("demo/**=protobuf")
            .expect("a keyexpr pattern");
        let named_run = Declarations::new(&named);
        match decode_payload(&put_declaring(ENC_JSON, protobuf), &named_run, at) {
            PayloadDecoding::Decoded {
                ref despite_encoding,
                ..
            } => assert!(
                despite_encoding.is_some(),
                "a format that NAMES its encodings does qualify its decode, so \
                 `None` above is a decision and not an empty field"
            ),
            other => panic!("the control must decode: {other:?}"),
        }
    }

    /// R311y874 — A DECLARATION ITS OWN BYTES CONTRADICT DOES NOT GET TO VETO
    /// THE RULE.
    ///
    /// # The defect this closes was made by the round before it
    ///
    /// R311y873 taught the field layer to check the sender's claim, on this
    /// crate's own rule that a claim is checked before it is believed. It then
    /// BELIEVED the claim — the veto fired on the strength of a declaration
    /// nobody had checked against the bytes it labels, which is the very thing
    /// `payload::inspect` exists to do.
    ///
    /// So the case that matters is the one where BOTH are wrong at once and
    /// only one of them is the reader's: a publisher that declares
    /// `application/json` and ships protobuf. The operator's rule is RIGHT, the
    /// publisher's label is WRONG, and R311y873 answered by hiding the data on
    /// the authority of the label. `inspect` can prove that label false in one
    /// call, and a veto resting on a claim this reader can refute is not a
    /// check — it is the same credulity the round was written against, pointed
    /// the other way.
    ///
    /// Both arms, because either alone passes on a wrong build. Severing the
    /// credibility question reds the first; deleting the veto outright reds the
    /// second, which is R311y873's own case and must still refuse.
    #[test]
    fn a_declaration_its_own_bytes_refute_does_not_veto_the_rule() {
        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        // field 1, varint, value 42 — valid protobuf, and not JSON at byte 0.
        let protobuf: &[u8] = &[0x08, 0x2a];

        let mislabelled = put_declaring(ENC_JSON, protobuf);
        let run = Declarations::new(&map);
        match decode_payload(&mislabelled, &run, at) {
            PayloadDecoding::Decoded {
                ref fields,
                ref despite_encoding,
                ..
            } => {
                assert_eq!(fields.len(), 1, "the operator's rule was the right one");
                assert_eq!(
                    despite_encoding.as_deref(),
                    Some("application/json"),
                    "decoding over a publisher's label is not the same fact as \
                     decoding under one, and a reader must be told which"
                );
            }
            other => panic!("a refuted label must not hide the data: {other:?}"),
        }

        // The vehicle for the veto itself: a label the bytes AGREE with still
        // wins, because there the rule is the thing that is wrong.
        let honest = put_declaring(ENC_JSON, br#"{"a":1}"#);
        let run = Declarations::new(&map);
        assert_eq!(
            decode_payload(&honest, &run, at),
            PayloadDecoding::EncodingMismatch {
                keyexpr: String::from("demo/a"),
                format: String::from("protobuf"),
                declared: String::from("application/json"),
                // Round 2025 (item 285) — CHECKED, and this leg's own sentence
                // says why: "a publisher whose bytes MATCH ITS OWN LABEL is
                // believed". That match is the measurement, and until this
                // round the verdict could not distinguish it from a veto where
                // nothing matched anything.
                checked: true,
            },
            "a publisher whose bytes match its own label is believed"
        );
    }

    /// R311y875 — THE RUN COUNTS ITS MISBOUND RULES, keyed on WHO IS WRONG.
    ///
    /// # Why this is a separate question from `unused`
    ///
    /// `unused` answers the rule that bound NOTHING: the pattern missed every
    /// topic. There was no answer at all for the rule that bound the WRONG
    /// thing — the pattern hit, and the traffic under it says the mapping and
    /// the wire disagree. Until this round both of those findings existed only
    /// per message, in a listing whose whole purpose is to be bounded.
    ///
    /// # Why the fixture is one topic and one label
    ///
    /// Three samples on `demo/a`, all declaring `application/json` under one
    /// `protobuf` rule, differing ONLY in the bytes: two the label refutes and
    /// one it bears out. So the two rows differ in `wrong` alone, which is what
    /// proves the tally is keyed on the verdict — a build keyed on the triple
    /// that produced it reports a single row of 3. The two counts differ, so
    /// neither can pass by being hard-coded, and the order is asserted because
    /// "most samples first" is what puts the larger finding where a reader
    /// looks.
    #[test]
    fn the_run_counts_which_rules_bound_the_wrong_thing() {
        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        // field 1, varint, value 42 — valid protobuf, and not JSON at byte 0.
        let refutes: &[u8] = &[0x08, 0x2a];
        let bears_out: &[u8] = br#"{"a":1}"#;

        let run = Declarations::new(&map);
        assert!(
            run.misbindings().is_empty(),
            "a run that has walked nothing has met no misbinding"
        );
        for bytes in [refutes, bears_out, refutes] {
            decode_payload(&put_declaring(ENC_JSON, bytes), &run, at);
        }

        assert_eq!(
            run.misbindings(),
            vec![
                Misbinding {
                    keyexpr: String::from("demo/a"),
                    format: String::from("protobuf"),
                    declared: String::from("application/json"),
                    wrong: Misbound::Publisher,
                    samples: 2,
                },
                Misbinding {
                    keyexpr: String::from("demo/a"),
                    format: String::from("protobuf"),
                    declared: String::from("application/json"),
                    wrong: Misbound::Rule,
                    samples: 1,
                },
            ],
            "two samples the label refutes are the PUBLISHER's finding and one \
             it bears out is the RULE's, counted apart and larger first"
        );

        // The ledger belongs to the RUN, on R311y726's rule for `unused`: a
        // second ledger over the same map has met nothing.
        assert!(
            Declarations::new(&map).misbindings().is_empty(),
            "a second run must not inherit the first run's findings"
        );
    }

    /// R311y926 (open-debt item 283) — THE `state` VOCABULARY IS TOTAL AND EACH
    /// WORD IS DISTINCT.
    ///
    /// The residue `PayloadDecoding::STATES`' own doc records: an author who
    /// points a new variant at an EXISTING index gets two variants rendering
    /// one word, and no compiler complains. Nothing asserted otherwise —
    /// `wz-capi-dissect` checks that the HEADER names every word, which says
    /// nothing about whether two variants share one.
    ///
    /// Asserted on the WALK rather than on a list, for the reason item 301
    /// settled a round earlier: a list is a second statement of the variant
    /// set, and a variant left out of it is not tested at all.
    #[test]
    fn every_decoding_state_has_its_own_word() {
        let all = PayloadDecoding::all();
        assert_eq!(
            all.len(),
            PayloadDecoding::STATES.len(),
            "every variant must have a word and every word a variant -- a walk \
             shorter than STATES means a variant is not linked into `next`"
        );
        let mut seen = BTreeSet::new();
        for decoding in &all {
            assert!(
                PayloadDecoding::STATES.contains(&decoding.state()),
                "{} names a word outside STATES",
                decoding.state()
            );
            assert!(
                seen.insert(decoding.state()),
                "two variants render the word `{}` -- an index was reused",
                decoding.state()
            );
        }
    }

    /// R311y875 — the `wrong` vocabulary is TOTAL and each word is distinct.
    ///
    /// `NAMES` is what `wz_dissect.h` documents in prose, and prose is the half
    /// no compiler holds.
    #[test]
    fn every_misbound_verdict_has_its_own_word() {
        // R311y925 (item 301) — WALKED, not written down. The list this opened
        // with was a second statement of the variant set, and a third variant
        // added without touching it was never visited by anything below.
        //
        // R311y926 (item 461) — what this asserts NARROWED, and deliberately.
        // It used to compare the walk against a hand-written `NAMES`, and that
        // comparison is gone because `NAMES` is gone: the list is now derived
        // from this same walk, so comparing them would be the walk agreeing
        // with itself. What was bought for it is worth more -- the chain is no
        // longer `cfg(test)`, so a variant missing an arm fails `cargo build`
        // rather than only a test build, which is exactly what item 461 asked
        // for.
        //
        // The claim left here is the one no compiler can make: two variants
        // must not SHARE a word. The other half of the old assertion moved to
        // `the_header_names_every_misbound_verdict`, which now iterates the
        // walk, so a new variant demands an entry in `wz_dissect.h` too.
        let all = Misbound::all();
        assert!(
            !all.is_empty(),
            "the walk visited no variant at all, so nothing below was measured"
        );
        let mut seen = BTreeSet::new();
        for verdict in all {
            assert!(
                seen.insert(verdict.name()),
                "{verdict:?} shares its word with another variant"
            );
        }
    }

    /// The vehicle, proved in the same round: the check must not cost the
    /// decode it guards.
    ///
    /// Two arms, and the second is the one that would break every capture
    /// already taken. `zenoh/bytes` is id 0 — what a publisher that set no
    /// encoding gets, which is the nanopb deployment this format exists for.
    /// Treating the DEFAULT as a contradiction would refuse the traffic the
    /// rule was written for, so silence is not a claim and does not veto.
    #[test]
    fn the_claim_the_rule_agrees_with_and_the_silence_that_is_no_claim_both_decode() {
        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);
        // field 1, varint, value 42.
        let body: &[u8] = &[0x08, 0x2a];

        for (encoding, why) in [
            (ENC_PROTOBUF, "the publisher's claim agrees with the rule"),
            (ENC_ZENOH_BYTES, "the publisher made no claim at all"),
        ] {
            let run = Declarations::new(&map);
            let decoded = decode_payload(&put_declaring(encoding, body), &run, at);
            match decoded {
                PayloadDecoding::Decoded { ref fields, .. } => {
                    assert_eq!(fields.len(), 1, "{why}: one field was sent");
                }
                other => panic!("{why}: expected a decode, got {other:?}"),
            }
        }
    }

    /// R311y856 — A DECLARATION THAT BOUND NOTHING IS STILL REPORTED, and the
    /// ledger belongs to the RUN rather than to the map.
    ///
    /// Both halves, because either alone passes on a wrong build. A ledger that
    /// recorded nothing would report both rules unused and look right on the
    /// first assertion's sibling; a ledger that lived on the map would report
    /// the second run's `other/b` correctly and quietly carry the first run's
    /// mark for `demo/a` — which is precisely the defect R311y726 moved this
    /// type out of `FormatMap` to end, and the reason a map must be consultable
    /// twice as if it were fresh.
    #[test]
    fn a_declaration_that_binds_nothing_is_still_reported() {
        let mut map = FormatMap::new();
        map.declare("demo/a=protobuf").expect("a literal pattern");
        map.declare("other/b=protobuf").expect("a literal pattern");

        let run = Declarations::new(&map);
        assert!(run.for_keyexpr("demo/a").is_some(), "the rule covers it");
        let left = run.unused();
        let unused: Vec<&str> = left.iter().map(|d| d.text.as_str()).collect();
        // R311y884 — `other/b=protobuf`, which is the line `declare` was given
        // three statements above. It used to read `other/b`: the ledger dropped
        // the half after the `=`, so the reported declaration was not one the
        // reader could have written (open-debt item 235).
        assert_eq!(
            unused,
            vec!["other/b=protobuf"],
            "the rule that met no traffic is the one a reader must be told about"
        );

        // The SAME map, a second run: nothing has applied yet.
        let fresh = Declarations::new(&map);
        assert_eq!(
            fresh.unused().len(),
            2,
            "a map is configuration and does not remember a previous walk"
        );
    }

    /// Round 2031 (item 300) — THE RUN COUNTS ITS REFUSALS, keyed on the claim
    /// the decoder ran under.
    ///
    /// # The harm this round measured before changing anything
    ///
    /// A probe drove all three arms and asserted what the plane said: for the
    /// first two, `misbindings()` was EMPTY — a decode that ran and failed
    /// reached nothing at all — and for the third the publisher's label was
    /// tallied while the refusal beside it was dropped on the floor. So a
    /// reader of that capture was told "the publisher is mislabelling" and was
    /// never told the rule had not read the bytes either. That probe passed,
    /// which is what made it a harm and not a hypothesis.
    ///
    /// # Why all three arms and not just the one the item names
    ///
    /// Item 300 is about the CORROBORATED arm, where the operator and the
    /// publisher agree and the reader's capture is genuinely the thing to look
    /// at. It is only distinguishable if the other two exist beside it: a plane
    /// that lumped "both agreed" together with "nobody claimed anything" would
    /// send a reader to their capture over traffic whose rule is a guess.
    ///
    /// Each arm is a separate leg with its own traffic, so no arm can pass by
    /// another arm's work — the class this session has paid for four times.
    #[test]
    fn the_run_counts_the_rules_it_applied_and_that_refused() {
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let spaces = KeyexprSpaces::new();
        let at = KeyexprAt::new(Direction::A, &spaces);

        // CORROBORATED: the publisher declares this decoder's own encoding and
        // the bytes are still not it. TWICE, so the count cannot pass by being
        // hard-coded to the one-sample answer.
        let run = Declarations::new(&map);
        let truncated = put_declaring(ENC_JSON, br#"{"a":"#);
        for _ in 0..2 {
            let seen = decode_payload(&truncated, &run, at);
            assert!(
                matches!(seen, PayloadDecoding::Refused { .. }),
                "the bytes are not JSON: {seen:?}"
            );
        }
        assert!(
            run.misbindings().is_empty(),
            "nothing is MISBOUND here -- neither side was caught out by the \
             other, which is why this is a third finding and not a third word \
             in that vocabulary"
        );
        let found = run.refusals();
        assert_eq!(found.len(), 1, "one topic, one rule, one claim: {found:?}");
        assert_eq!(found[0].under, RefusedUnder::Corroborated);
        assert_eq!(found[0].samples, 2, "both samples: {found:?}");
        assert_eq!(found[0].keyexpr, "demo/a");
        assert_eq!(found[0].format, "json");
        assert!(
            !found[0].example.is_empty(),
            "and ONE reason rides along: {found:?}"
        );
        assert!(
            found[0].sentence().contains("look at the capture"),
            "this arm's whole value is where it sends a reader: {}",
            found[0].sentence()
        );

        // UNCLAIMED: id 0 is a publisher saying nothing, so the rule is the
        // only claim there is and the traffic contradicts it.
        let run = Declarations::new(&map);
        let bare = put_declaring(ENC_ZENOH_BYTES, br#"{"a":"#);
        let seen = decode_payload(&bare, &run, at);
        assert!(
            matches!(seen, PayloadDecoding::Refused { .. }),
            "the bytes are not JSON: {seen:?}"
        );
        let found = run.refusals();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].under,
            RefusedUnder::Unclaimed,
            "`zenoh/bytes` is SILENCE, not corroboration -- a build that read \
             the benefit of the doubt as evidence would send this reader to \
             their capture over a rule that is only a guess: {found:?}"
        );
        assert!(
            found[0].sentence().contains("--payload-format"),
            "and this arm names the flag instead: {}",
            found[0].sentence()
        );

        // REFUTED: the label says text, its own bytes refute that, the rule is
        // applied over the label -- and refuses too.
        let run = Declarations::new(&map);
        let both_wrong = put_declaring(ENC_TEXT_PLAIN, &[0xFF, 0xFE]);
        let seen = decode_payload(&both_wrong, &run, at);
        assert!(
            matches!(seen, PayloadDecoding::Refused { .. }),
            "neither claim reads these bytes: {seen:?}"
        );
        assert_eq!(
            run.misbindings().len(),
            1,
            "the label is still a misbinding: {seen:?}"
        );
        let found = run.refusals();
        assert_eq!(
            found.len(),
            1,
            "AND the refusal beside it is a finding of its own -- this is the \
             asymmetry item 300 names: {found:?}"
        );
        assert_eq!(found[0].under, RefusedUnder::Refuted);
        assert!(
            found[0].sentence().contains("both wrong"),
            "so the sentence says both: {}",
            found[0].sentence()
        );

        // A map is configuration: a second run over it remembers nothing.
        let fresh = Declarations::new(&map);
        assert!(fresh.refusals().is_empty());
    }

    /// Round 2031 (item 300) — EVERY refusal word is distinct, and the walk
    /// visits every arm without a list to keep true.
    ///
    /// [`Misbound`]'s own gate, on the vocabulary introduced this round rather
    /// than after a prose copy of it has drifted — R311y926's lesson applied
    /// forwards: an arm added later that reuses another arm's word compiles and
    /// ships, and only a distinctness test catches it.
    #[test]
    fn every_refusal_claim_has_its_own_word() {
        let words = RefusedUnder::names();
        assert_eq!(words.len(), 3, "the walk visits every arm: {words:?}");
        let unique: alloc::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(
            unique.len(),
            words.len(),
            "two claims sharing a word makes a C consumer's branch silently \
             wrong on real traffic: {words:?}"
        );
    }

    /// R311y856 — the emit is TOTAL over the type, including the state a caller
    /// is expected to skip.
    ///
    /// `NoRules` renders rather than panicking: an `unreachable!` here would
    /// turn a caller's ordering mistake into a panic inside a library a C
    /// consumer links, which is a worse failure than an odd-looking document.
    #[test]
    fn every_state_renders_and_none_of_them_panics() {
        let states = [
            PayloadDecoding::NoRules,
            PayloadDecoding::NoPayload,
            PayloadDecoding::KeyexprUnresolved,
            PayloadDecoding::NoRule(String::from("demo/\"quoted\"")),
            PayloadDecoding::Refused {
                keyexpr: String::from("demo/a"),
                format: String::from("protobuf"),
                why: String::from("these bytes are not this format"),
            },
            PayloadDecoding::EncodingMismatch {
                keyexpr: String::from("demo/\"quoted\""),
                format: String::from("protobuf"),
                declared: String::from("application/json"),
                checked: true,
            },
        ];
        for state in &states {
            let mut out = String::new();
            push_decoding(state, &mut out);
            assert!(
                out.starts_with("{\"state\":\"") && out.ends_with('}'),
                "every state renders one object: {out}"
            );
        }
        // And the keyexpr is ESCAPED rather than pasted: it is text off the
        // wire, and a quote in it would end the JSON string early.
        let mut out = String::new();
        push_decoding(&states[3], &mut out);
        assert!(
            out.contains(r#""demo/\"quoted\"""#),
            "a keyexpr carrying a quote must be escaped: {out}"
        );
    }
}

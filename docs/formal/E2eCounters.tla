---------------------------- MODULE E2eCounters -----------------------------
(***************************************************************************)
(* How a sender and a receiver of end-to-end protected frames keep         *)
(* E2eCounterService (S11 3 and S10 8 of docs/zenoh-logic-as-sce-kinds.md, *)
(* W12; level 2 of SCE ADR 0115, D2): the counter the sender writes and    *)
(* its rollover, sources/algorithms/counter_after.scxml, and the step and  *)
(* verdict the receiver judges by,                                         *)
(* sources/algorithms/e2e_counter_step.scxml and                           *)
(* e2e_counter_verdict.scxml.                                              *)
(*                                                                         *)
(* The sender writes its next value into each message it takes, then asks  *)
(* counter_after: the next value below the field's largest, Max; past it 0 *)
(* when it wraps, or none, after which it refuses every message. A message *)
(* it refuses (a payload too long, a buffer too short, no value left) does *)
(* not ask it, and so consumes no value. The receiver takes the step of a  *)
(* frame's counter from its baseline modulo the ring of the field, Max +   *)
(* 1, and judges it: 0 a repetition, 1 to MaxGap in range, above out of    *)
(* range.                                                                  *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Max is the field's largest value, 2^width - 1, and the receiver takes *)
(*     its step in the same width: both are width_mask of the counter's    *)
(*     bytes, `crates/wz-app-schema/src/e2e_profile.rs` @ `width_mask((self.bytes * 8) as u8)`. *)
(*   MaxGap is below the ring: the profile refuses a max_gap above Max,    *)
(*     `crates/wz-app-schema/src/e2e_profile.rs` @ `if max_gap == 0 || max_gap > fields[field].max_value() {`. *)
(*   A stream loses fewer than a ring of frames in a row (Horizon = Max),  *)
(*     and does not reorder them.                                          *)
(*   One sender writes one stream, and nothing sets its value meanwhile    *)
(*     (StreamSender::set and SegmentSender::set are not modelled).        *)
(*                                                                         *)
(* What the upstream presets do: neither zenoh nor zenoh-pico has an       *)
(* end-to-end counter; the frame is the application's payload, which both  *)
(* carry as opaque bytes.                                                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Max,          \* the counter field's largest value, 2^width - 1
          MaxGap,       \* the profile's max_gap
          Horizon,      \* how far on a frame may be: fewer than a ring
          Sends,        \* the most messages a run takes, which bounds the exploration
          First,        \* the value the sender is made with
          Wraps,        \* Rollover::Wrap; FALSE is Rollover::Refuse
          RefusalKeeps, \* a refused message consumes no value (counter_after is not asked)
          WrapToZero,   \* past Max the sender restarts at 0; off, at First (the segment rule)
          RepeatAtZero, \* a step of 0 is a repetition (e2e_counter_verdict's first guard)
          GapBound,     \* a step is in range only up to MaxGap (its second guard)
          NoValue       \* a model value: no value left, or no baseline yet

VARIABLES next,    \* the value the next message carries, or NoValue
          wire,    \* wire[k]: the counter message k carried
          base,    \* the receiver's baseline counter, or NoValue before the first frame
          judged,  \* the message the baseline came from: the refinement's witness, which
                   \* the receiver never reads
          dist,    \* how many messages on the last frame judged was: Exact's witness
          said     \* the last verdict: <<message, kind, step>>

vars == <<next, wire, base, judged, dist, said>>

Ring == Max + 1

\* sources/algorithms/counter_after.scxml, asked with the sender's rollover.
After(s) == IF s < Max THEN s + 1
            ELSE IF Wraps THEN (IF WrapToZero THEN 0 ELSE First)
            ELSE NoValue

\* e2e_counter_step: wrappingSub(counter, baseline) & mask.
Step(c, b) == (c + Ring - b) % Ring

\* e2e_counter_verdict.
Verdict(s) == IF s = 0 /\ RepeatAtZero THEN "repeat"
              ELSE IF s <= MaxGap \/ ~GapBound THEN "inrange"
              ELSE "outofrange"

Init == /\ next = First
        /\ wire = <<>>
        /\ base = NoValue
        /\ judged = 0
        /\ dist = 0
        /\ said = <<>>

Take == /\ next # NoValue /\ Len(wire) < Sends
        /\ wire' = Append(wire, next)
        /\ next' = After(next)
        /\ UNCHANGED <<base, judged, dist, said>>

Refuse == /\ Len(wire) < Sends
          /\ next' = IF RefusalKeeps \/ next = NoValue THEN next ELSE After(next)
          /\ UNCHANGED <<wire, base, judged, dist, said>>

Baseline(i) == /\ base = NoValue
               /\ base' = wire[i]
               /\ judged' = i
               /\ dist' = 0
               /\ said' = <<i, "first", 0>>

Judge(i) == /\ base # NoValue /\ judged <= i /\ i <= judged + Horizon
            /\ LET s == Step(wire[i], base)
                    v == Verdict(s)
               IN /\ said' = <<i, v, s>>
                  /\ dist' = i - judged
                  /\ base' = IF v = "repeat" THEN base ELSE wire[i]
                  /\ judged' = IF v = "repeat" THEN judged ELSE i

Receive(i) == /\ Baseline(i) \/ Judge(i)
              /\ UNCHANGED <<next, wire>>

Next == Take \/ Refuse \/ \E i \in 1..Len(wire) : Receive(i)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* What the last frame was judged is what it is: a repetition exactly when it is the baseline's
\* message again, in range exactly when it is 1 to MaxGap messages on, and its step the number
\* of messages on, so a refused message is never counted as lost.
Kind(d) == IF d = 0 THEN "repeat" ELSE IF d <= MaxGap THEN "inrange" ELSE "outofrange"

Exact == said = <<>> \/ said[2] = "first" \/ said = <<said[1], Kind(dist), dist>>

-----------------------------------------------------------------------------
\* What the protocol implements (SCE ADR 0115, D2): the service a receiver relies on.
Service == INSTANCE E2eCounterService WITH
    MaxGap <- MaxGap,
    Horizon <- Horizon,
    Sends <- Sends,
    sent <- Len(wire),
    judged <- judged,
    said <- said

Refines == Service!Spec

=============================================================================

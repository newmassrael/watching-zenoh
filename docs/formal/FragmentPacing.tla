--------------------------- MODULE FragmentPacing ---------------------------
(***************************************************************************)
(* How a datagram link's writer keeps FragmentPacingService: the pacer of  *)
(* the datagram-fragment-pacing policy (S1 29 of                           *)
(* docs/zenoh-logic-as-sce-kinds.md; level 2 of SCE ADR 0115, D2). The     *)
(* rule is sources/algorithms/fragment_pacing_wait.scxml, which             *)
(* crates/wz-session-core/src/fragment_pacing.rs asks before each          *)
(* datagram and gives the pacer's run back to.                             *)
(*                                                                         *)
(* The pacer holds the run, the fragments written since the last wait or   *)
(* the last datagram that was not a fragment, and when the last datagram   *)
(* was written. A datagram that is not a fragment ENDS THE RUN and is      *)
(* written at once. A fragment of a run that has reached Burst is HELD     *)
(* until Gap after the last write, the time already passed SUBTRACTED, and *)
(* the run RESTARTS at one; any other fragment is written at once and      *)
(* counted.                                                                *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   A write takes no time: the pacer is told of a write when it has      *)
(*     returned, so the gap runs from the end of the last write to the     *)
(*     start of the next,                                                  *)
(*     `crates/wz-runtime-tokio/src/datagram_pacing.rs` @ `        self.pacer.wrote(now);`.  *)
(*   A wait ends when it was asked to; a timer that wakes later only       *)
(*     lengthens it, which BoundedDelay does not cover.                    *)
(*   The clock does not go back: a reading earlier than the last write is  *)
(*     read as no time passed (the saturating subtraction), not modelled.  *)
(*   One writer asks for one datagram at a time, from one task.            *)
(*                                                                         *)
(* What the upstream presets do: neither zenoh nor zenoh-pico paces the    *)
(* fragments of a message; the policy's other value, upstream's, holds no  *)
(* pacer and writes as fast as the socket takes them.                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Burst, Gap, MaxTime,
          MaxLen,    \* the datagrams a behaviour writes (bounds the exploration)
          Hold,      \* a fragment of a run that reached Burst waits (the document's held step)
          EndRun,    \* a datagram that is not a fragment ends the run (the run given back as 0)
          Restart,   \* the run starts again at one after a held fragment (not counted on)
          Subtract   \* a held fragment waits Gap less the time since the last write, not Gap

VARIABLES now,       \* the time
          log,       \* the datagrams written: <<kind, asked, written>>, in order
          run,       \* the pacer's run
          writtenAt  \* when the last datagram was written

vars == <<now, log, run, writtenAt>>

Kinds == {"fragment", "other"}

Monus(a, b) == IF a >= b THEN a - b ELSE 0

\* The document's three steps: <<wait, run given back>>.
Step(k) ==
    IF k = "other"
    THEN <<0, IF EndRun THEN 0 ELSE run>>
    ELSE IF Hold /\ run >= Burst
         THEN <<IF Subtract THEN Monus(Gap, Monus(now, writtenAt)) ELSE Gap,
                IF Restart THEN 1 ELSE run + 1>>
         ELSE <<0, run + 1>>

Init == /\ now = 0
        /\ log = <<>>
        /\ run = 0
        /\ writtenAt = 0

Tick == /\ now < MaxTime
        /\ now' = now + 1
        /\ UNCHANGED <<log, run, writtenAt>>

\* The writer asks the pacer at now, waits what it answers, writes, and tells the pacer.
Write(k) == LET s == Step(k)
                at == now + s[1]
            IN /\ Len(log) < MaxLen
               /\ log' = Append(log, <<k, now, at>>)
               /\ run' = s[2]
               /\ writtenAt' = at
               /\ now' = at

Next == Tick \/ \E k \in Kinds : Write(k)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Service == INSTANCE FragmentPacingService WITH
    Burst <- Burst,
    Gap <- Gap,
    MaxTime <- MaxTime,
    now <- now,
    log <- log

Spaced == \A i \in 1..Len(log) : Service!SpacedAt(log, i)

BoundedDelay == \A i \in 1..Len(log) : Service!BoundedDelayAt(log, i)

LetsBurst == \A i \in 1..Len(log) : Service!LetsBurstAt(log, i)

\* What the protocol implements (SCE ADR 0115, D2): the service a sender relies on.
Refines == Service!Spec

=============================================================================

------------------------- MODULE E2eCounterService --------------------------
(***************************************************************************)
(* What a receiver of one stream of end-to-end protected frames may rely   *)
(* on of the numbers its sender puts on them (level 1 of SCE ADR 0115,     *)
(* D1). No counter, field width, rollover or step is in it.                *)
(*                                                                         *)
(* The sender TAKES messages one after another; a message it refuses is    *)
(* not taken and leaves no trace on the stream. The receiver judges each   *)
(* frame it is handed against the last one it took as its baseline. A      *)
(* frame of the baseline's message again is a REPETITION. A frame of a     *)
(* later message is IN RANGE when it is at most MaxGap messages on, and    *)
(* reports how many messages on it is, so the messages lost between the    *)
(* two are counted exactly and a refused message is never counted as lost; *)
(* further on it is OUT OF RANGE. Either moves the baseline to the frame;  *)
(* a repetition does not. The first frame is the first baseline.           *)
(*                                                                         *)
(* Horizon is how far on a frame may be for the promise to hold: a stream  *)
(* that loses a whole ring of numbers in a row cannot be told from one     *)
(* that lost none, whatever the mechanism.                                 *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   The stream loses and repeats frames but does not reorder them.        *)
(*   Nothing else: it is what a receiver may rely on, and names no         *)
(*     mechanism.                                                          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxGap,   \* the most messages on a frame is judged in range
          Horizon,  \* the most messages on a frame may be for the promise to hold
          Sends     \* the most messages a run takes, which bounds the exploration

VARIABLES sent,    \* the messages taken, numbered 1..sent
          judged,  \* the message of the receiver's baseline; 0 before the first frame
          said     \* the last verdict: <<message, kind, messages on from the baseline>>

vars == <<sent, judged, said>>

Kind(d) == IF d = 0 THEN "repeat" ELSE IF d <= MaxGap THEN "inrange" ELSE "outofrange"

Init == /\ sent = 0
        /\ judged = 0
        /\ said = <<>>

Take == /\ sent < Sends
        /\ sent' = sent + 1
        /\ UNCHANGED <<judged, said>>

First(i) == /\ judged = 0
            /\ judged' = i
            /\ said' = <<i, "first", 0>>

Judge(i) == /\ judged # 0 /\ judged <= i /\ i <= judged + Horizon
            /\ said' = <<i, Kind(i - judged), i - judged>>
            /\ judged' = i

Receive(i) == /\ First(i) \/ Judge(i)
              /\ UNCHANGED sent

Next == Take \/ \E i \in 1..sent : Receive(i)

Spec == Init /\ [][Next]_vars

=============================================================================

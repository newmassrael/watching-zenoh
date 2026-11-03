# Declarations synced event

`declarations-synced-event` (capability, off by default, `WZ_CAP_DECLARATIONS_SYNCED_EVENT`) tells a
declaration listener that the peer has sent everything it held. It is wz's own: no upstream library
reports it, so it is off in every original.

## The problem it answers

A session learns what its peer has declared as a stream: a `DeclSubscriber` here, a `DeclToken`
there, then more as the peer's application declares more. A listener sees `Declared` events and
nothing tells it where the peer's picture of itself ends and live changes begin. That boundary
matters to a program that reads "no subscriber on this key" as "nobody wants it": before the
boundary the answer may simply not have arrived. The write filter of a publisher has always needed
the same fact, which is why the subscriber plane tracks it (`initial_declarations_final`).

On the wire the boundary is one message: the `DeclareFinal` of the initial interest
(`INITIAL_INTEREST_ID`), sent after the peer's first burst of subscribers, queryables and tokens.
One message ends all three, so the fact belongs to the peer, not to a plane.

## What a listener sees

`DeclEvent::Synced` is delivered to every declaration listener (`declare_remote_subscriber_listener`,
`declare_remote_queryable_listener`, `declare_remote_token_listener`), once, in the dispatch that
carries the final, after the `Declared` events that dispatch produced. Every `Declared` before it is
what the peer held when the session was established; every one after is live.

* A final of another interest is another plane's answer and tells nobody.
* A peer that repeats its final has said nothing new: nobody is told twice.
* The link being lost clears the fact with the declarations; the next establishment ends with its
  own `Synced`.
* A listener declared after the peer finished is not told: it was not given what came before, so
  the event would claim a completeness it does not have. It reads
  `Session::peer_declarations_final()`.

It is not `Session::declarations_synced`, which is the other direction: whether this node's
declarations have reached the peer (`docs/declaration-sync-pacing.md`).

## Where it lives

* `wz_session_core::decl_sink::SyncedSinks`, held by the observer as `declarations_final`: the
  observers, id-keyed like the pair's, so a listener removes its own on undeclare.
* The host session reads the subscriber plane's flag before and after it dispatches an event, and
  fires the observers on the dispatch that turns it on. The observer does not fire it itself,
  because the flag lives on one plane and the observers listen on three.
* Each listener stages `Synced` onto its deferred cell, as it stages the others, so the callback
  runs after the observer lock drops.

## What it costs

Nothing without the feature: the variant exists (the enum is `non_exhaustive`, so a match on it
already has a fallback), nothing is installed and nothing is fired. With it, a listener holds one
more observer, and a dispatch reads one flag twice.

## Not yet

The unicast host session only. A multicast session has no single peer and no initial interest, and
the C ABIs have no door for it: a capability that exports one is a separate step. The router's face
tracks the same fact for its own purposes (`initial_final` on the face) and does not tell a
listener.

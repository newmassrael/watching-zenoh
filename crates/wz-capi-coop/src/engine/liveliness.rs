// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness plane on the cooperative engine: the tokens the session holds, and the
//! subscribers that hear the ones its peer holds.
//!
//! A token is announced to the peer the session's link reaches, and again over each link that
//! comes up after; it is also registered with the observer's local tokens, so a peer that asks
//! for the tokens alive later is answered with it, as zenoh-pico keeps every token it declares
//! (`vendor/zenoh-pico/src/net/liveliness.c` @
//! `_z_declared_keyexpr_intmap_insert(&_Z_RC_IN_VAL(zn)->_local_tokens, id, ke_on_heap) == NULL) {`).
//!
//! A liveliness subscriber is a row of the session's tables ([`LivelinessRow`]), its id the one its
//! Interest carries, and its Interest is sent again over each new link. What reaches its row
//! does so under the session's lock, and a C callback never runs there (decision D8), so a call
//! is begun on the row and the sample held in the session's round of deliveries (`crate::round`):
//! a token declared, retracted or gone with a lost link. The deliveries hand them out with no lock
//! held; the tokens alive when the subscriber asked for its history are handed on the declaring
//! thread.

use core::ptr::NonNull;

use wz_capi_port::{LivelinessSink, SubId, TokenId, WireKey};
#[cfg(feature = "group")]
use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::declare::liveliness_sample::LivelinessSample;
#[cfg(feature = "group")]
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::named_key::NamedKey;
use wz_session_core::row_callback::{CallLatch, RowCallback};
use wz_session_core::session_tables::LivelinessSubscriberHandle;
#[cfg(feature = "group")]
use wz_session_core::session_tables::WireForm;
use wz_session_core::wire_id::ExprId;
use wz_session_mcu::dial::McuActions;

#[allow(unused_imports)]
use crate::prelude::*;

/// The ABI's form of a key the session's tables name `form` on the wire, for a group told the
/// entity it names.
#[cfg(feature = "group")]
fn wire_key_of(form: WireForm<'_>) -> WireKey {
    if form.mapping == 0 {
        return WireKey::literal();
    }
    WireKey::aliased(
        form.mapping,
        (!form.suffix.is_empty()).then(|| String::from(form.suffix)),
    )
}

/// Announce the token `id` the session holds on `key` over `actions`, its key named as the
/// session's tables name it or as the link's key-wire form says: whether the link took it.
pub(super) fn declare_token<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    id: TokenId,
    key: NamedKey<'_>,
) -> bool {
    actions
        .send_declare_token(id, super::key_on_link(actions, key))
        .is_ok()
}

#[cfg(feature = "group")]
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> super::Core<L, C> {
    /// Tell each group the session joined of the token `handle` names, as its row in the
    /// session's tables states it (`group`).
    pub(super) fn announce_token_to_groups(
        &self,
        handle: wz_session_core::session_tables::TokenHandle,
    ) {
        let tables = super::tables(&self.registry);
        let Some(row) = tables.tokens().get(handle) else {
            return;
        };
        let form = tables.wire_of(row.key());
        let wire = wire_key_of(form);
        let retraction = row.key().names_key().then(|| RetractionKey {
            mapping_id: form.mapping,
            suffix: String::from(form.suffix),
        });
        self.announce_to_groups(super::group::GroupEntity {
            what: wz_session_core::declare_form::GroupDeclaration::Token,
            entity: row.id(),
            keyexpr: row.key().as_str(),
            wire: &wire,
            retraction: retraction.as_ref(),
            allowed_origin: wz_session_core::locality::Locality::Any,
        });
    }
}

/// Retract the token `id` over `actions`, naming its key as `names` says (the declaration's id
/// and the rest of the key) when its declaration asked to.
pub(super) fn retract_token<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    id: TokenId,
    names: Option<(ExprId, &str)>,
) {
    let id = u64::from(id);
    match names {
        Some((mapping, suffix)) => actions.send_undeclare_token_naming(id, mapping, suffix),
        None => actions.send_undeclare_token(id),
    }
}

/// One of the session's own liveliness subscribers, as a row of the session's tables holds it: the
/// row keeps the key it hears and whether it asked for the tokens alive at its declaration, and
/// this the rest the session knows of it: the key as the ABI named it, which its Interest names the
/// key by, and its callback. The subscriber is that one row (`docs/c-abi-architecture.md`, P1),
/// and so is its callback's life (P11): a call is begun on the row's latch with the session held
/// and made after it, and an undeclared row is let go of by whoever sees its last call end.
pub(crate) struct LivelinessRow {
    /// The key as the ABI named it: what the subscriber's Interest names its key by on a link of
    /// the ABI's form and what a group is asked by, and what it keeps alive (the declaration the
    /// ABI made it on), let go of with the row, with no lock of the session held.
    wire: WireKey,
    /// The program's callback, called where the row lies: the tables lend their rows from the
    /// session's arena and never move one.
    sink: LivelinessSink,
    /// How many calls of the callback run, and whether the subscriber was undeclared.
    latch: CallLatch,
}

impl LivelinessRow {
    /// A subscriber on `wire` as the ABI named its key, handing what it hears to `sink`.
    pub(crate) fn new(wire: WireKey, sink: LivelinessSink) -> Self {
        Self {
            wire,
            sink,
            latch: CallLatch::new(),
        }
    }

    /// The key as the ABI named it, which a group is asked by.
    #[cfg(feature = "group")]
    pub(super) fn wire(&self) -> &WireKey {
        &self.wire
    }

    /// Hand `sample` to the callback, unless the subscriber was undeclared since the call was
    /// begun: the one place a token's change is handed to a liveliness subscriber's callback.
    fn hand(&self, sample: LivelinessSample<'_>) {
        if !self.latch.retired() {
            self.sink.call(sample);
        }
    }

    /// Send the Interest of subscriber `id` on `keyexpr` over `actions`: the tokens to come, and
    /// with `history` the ones alive now, its key named as the link's key-wire form says: whether
    /// the link took it.
    pub(super) fn ask<C: ClockSource + 'static>(
        &self,
        id: SubId,
        keyexpr: &str,
        history: bool,
        actions: &McuActions<C>,
    ) -> bool {
        let id = u64::from(id);
        let wire = super::on_link(actions, keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_interest_liveliness_subscriber(id, history, 0, Some(keyexpr))
        } else {
            actions.send_interest_liveliness_subscriber(
                id,
                history,
                wire.mapping_id,
                wire.suffix.as_deref(),
            )
        }
        .is_ok()
    }
}

/// A call of a liveliness subscriber's callback, begun on its row's latch: where the row lies.
pub(crate) struct LivelinessRowCall(NonNull<LivelinessRow>);

impl RowCallback for LivelinessRow {
    type Call = LivelinessRowCall;

    const READS_ROW_IN_PLACE: bool = true;

    fn begin(&self) -> Option<LivelinessRowCall> {
        self.latch
            .begin()
            .then(|| LivelinessRowCall(NonNull::from(self)))
    }

    unsafe fn end(call: LivelinessRowCall) -> bool {
        // SAFETY: the caller's: the row has not moved since the call began and is still in its
        // table, which keeps it until its last call ended.
        unsafe { call.0.as_ref() }.latch.end()
    }

    fn retire(&self) -> bool {
        self.latch.retire()
    }
}

/// A call of a liveliness subscriber's callback the session began under its lock and a delivery
/// makes after it, as a subscriber's ([`super::SubscriberCall`]): the call, and the handle its row
/// is let go of by when it ends the last call of an undeclared subscriber. Each is ended once
/// ([`Self::end`]), or its row would keep its slot for good.
#[must_use = "a call is ended, or its row is never let go of"]
pub(crate) struct LivelinessCall {
    call: LivelinessRowCall,
    handle: LivelinessSubscriberHandle,
}

impl LivelinessCall {
    /// `call`, begun on the row `handle` names.
    pub(crate) fn new(call: LivelinessRowCall, handle: LivelinessSubscriberHandle) -> Self {
        Self { call, handle }
    }

    /// Whether `other` is a call of the same row.
    pub(crate) fn same_row(&self, other: &Self) -> bool {
        self.call.0 == other.call.0
    }

    /// Hand `sample` to the row's callback.
    pub(crate) fn hand(&self, sample: LivelinessSample<'_>) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a row's sink after it is declared.
        unsafe { self.call.0.as_ref() }.hand(sample);
    }

    /// End the call: the handle of its row when it was the last call of an undeclared subscriber,
    /// which the caller lets go of (`SessionTables::release_liveliness_subscriber`).
    pub(crate) fn end(self) -> Option<LivelinessSubscriberHandle> {
        // SAFETY: the row lies where the call began (the tables never move a row) and keeps its
        // slot until its last call ended, which this one is not yet; a call ends with no lock held
        // (`CallLatch::ENDS_HELD` is asserted false where the rows are chosen).
        let last = unsafe { <LivelinessRow as RowCallback>::end(self.call) };
        last.then_some(self.handle)
    }
}

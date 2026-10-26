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
//! A liveliness subscriber is the observer's, registered under the id its Interest carries, and
//! its Interest is sent again over each new link. What the observer hands its sink happens under
//! the session's lock, and a C callback never runs there (decision D8), so the sink only queues
//! an owned copy of each sample: a token declared, retracted, already alive when the subscriber
//! asked for its history, or gone with a lost link. The deliveries hand them out with no lock
//! held.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use wz_capi_port::os::Mutex;

use wz_capi_port::{SubId, TokenId, WireKey};
use wz_runtime_coop::ClockSource;
use wz_session_core::declare::liveliness_sample::{
    BoxedLivelinessSampleSink, LivelinessSample, LivelinessSampleKind,
};
use wz_session_core::declare_form::RetractionKey;
use wz_session_mcu::dial::McuActions;

use super::lock;
#[allow(unused_imports)]
use crate::prelude::*;

/// A liveliness subscriber's callback, as the ABI's sink minted it, locked while it runs as a
/// subscriber's is.
pub(super) type LivelinessCallback =
    Arc<Mutex<Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send + 'static>>>;

/// The samples the liveliness subscribers' sinks queued, in the order they happened.
pub(super) type LivelinessQueue = Arc<Mutex<VecDeque<(SubId, OwnedLivelinessSample)>>>;

/// A token the session holds: what its declaration says on the wire, kept to announce it again
/// over a new link; holding the key also keeps alive what it holds.
pub(super) struct TokenEntry {
    pub(super) id: TokenId,
    pub(super) keyexpr: String,
    pub(super) wire: WireKey,
    pub(super) retraction: Option<RetractionKey>,
}

impl TokenEntry {
    /// Announce this token over `actions`: whether the link took it.
    pub(super) fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        if self.wire.is_literal() {
            actions.send_declare_token(self.id, 0, Some(&self.keyexpr))
        } else {
            actions.send_declare_token(self.id, self.wire.mapping_id, self.wire.suffix.as_deref())
        }
        .is_ok()
    }

    /// Retract this token over `actions`, naming its key when its declaration asked to.
    pub(super) fn retract<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        match &self.retraction {
            Some(key) => actions.send_undeclare_token_naming(self.id, key.mapping_id, &key.suffix),
            None => actions.send_undeclare_token(self.id),
        }
    }
}

/// A liveliness subscriber the session holds: what its Interest asks, kept to ask it again over a
/// new link.
pub(super) struct LiveSubEntry {
    /// Its id, which is also its Interest's, as zenoh-pico's subscription id is.
    pub(super) id: SubId,
    pub(super) keyexpr: String,
    pub(super) wire: WireKey,
    pub(super) history: bool,
}

impl LiveSubEntry {
    /// Send this subscriber's Interest over `actions`: the tokens to come, and with `history` the
    /// ones alive now: whether the link took it.
    pub(super) fn ask<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        if self.wire.is_literal() {
            actions.send_interest_liveliness_subscriber(
                self.id,
                self.history,
                0,
                Some(&self.keyexpr),
            )
        } else {
            actions.send_interest_liveliness_subscriber(
                self.id,
                self.history,
                self.wire.mapping_id,
                self.wire.suffix.as_deref(),
            )
        }
        .is_ok()
    }
}

/// A liveliness sample as the observer handed it, owned, so it outlives the lock it was handed
/// out under.
pub(super) struct OwnedLivelinessSample {
    kind: LivelinessSampleKind,
    keyexpr: String,
    token_id: u64,
}

impl OwnedLivelinessSample {
    /// The sample, borrowed again for its callback.
    pub(super) fn as_sample(&self) -> LivelinessSample<'_> {
        LivelinessSample {
            kind: self.kind,
            keyexpr: &self.keyexpr,
            token_id: self.token_id,
        }
    }
}

/// The sink subscriber `id` is registered with: each sample is queued as an owned copy.
pub(super) fn sample_sink(id: SubId, queue: &LivelinessQueue) -> BoxedLivelinessSampleSink {
    let queue = Arc::clone(queue);
    BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
        lock(&queue).push_back((
            id,
            OwnedLivelinessSample {
                kind: sample.kind,
                keyexpr: sample.keyexpr.to_owned(),
                token_id: sample.token_id,
            },
        ));
    })
}

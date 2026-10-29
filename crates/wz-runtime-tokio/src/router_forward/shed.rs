// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Closing the newest sessions when the router holds more than it can keep the leases of.
//!
//! The router admits sessions up to a bound it derives from what a keepalive emission costs on
//! its host ([`wz_session_core::capacity::effective_max_sessions`]), and that cost is only known
//! as it is paid: a router that admits while its host is quiet reads a cost the load that comes
//! later multiplies by 15 or more. The sessions admitted at the quiet cost can then be more than
//! the loaded host serves, and without this their keepalives fall further behind each interval
//! until the leases of all of them, the older ones included, run out.
//!
//! [`crate::capacity_control`] closes the loop on the lateness of the keepalive timers
//! ([`wz_session_core::capacity::AdmissionControl`]) and asks this registry to keep fewer. The
//! registry is not the forwarder's face table: that is the loop's, behind an `Rc`, and a router
//! that is short of CPU is exactly the one whose loop is not running when it is needed. The
//! registry holds the one thing shedding needs of a session, the handle that asks it to close,
//! behind a lock, so that a thread of the control runtime can shed without the loop.
//!
//! The close is the one a send that could not wait would have made (`UNRESPONSIVE`, the reason
//! upstream closes a transport it cannot serve), so a peer that finds itself closed this way knows
//! the router, and not its own link, is what could not keep up. It takes effect at once, on the
//! thread that asks: the session's keepalives stop, and the peer is told on the urgent write
//! (`SessionLinkActions::close_for_capacity`). The session leaves the router when its drive loop
//! gets to the close, which on a router that is short of CPU is seconds, and the keepalives of a
//! session that is on its way out are exactly the load the cut was meant to take off. The
//! sessions closed are the newest: the router has kept those held longest for longest, and a peer
//! that was refused is no worse off than one admitted a moment before the load came.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::accept_loop::FaceId;
use crate::session_glue::SessionLinkActions;

/// One session of the registry: how to ask it to close, and whether that was done.
struct Held {
    actions: Arc<SessionLinkActions>,
    shedding: bool,
}

/// The sessions a router holds, as far as shedding needs them.
#[derive(Default)]
pub struct ShedRegistry {
    held: Mutex<BTreeMap<FaceId, Held>>,
    shed: std::sync::atomic::AtomicUsize,
}

impl ShedRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<FaceId, Held>> {
        // A panic while the lock was held left a map of handles, which is still a map of handles.
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A session of the router, held from now.
    pub(crate) fn add(&self, id: FaceId, actions: Arc<SessionLinkActions>) {
        self.lock().insert(
            id,
            Held {
                actions,
                shedding: false,
            },
        );
    }

    /// A session the router no longer holds.
    pub(crate) fn remove(&self, id: FaceId) {
        self.lock().remove(&id);
    }

    /// Ask the session `id` to close because a second link to its node has come up and is the
    /// one to keep ([`SessionLinkActions::close_for_replacement`]). `true` when the router
    /// holds the session and it was asked; the session leaves when its drive loop gets to the
    /// close. The handle is taken under the lock and used outside it, so the close, which writes,
    /// never holds the registry.
    pub(crate) fn close_replaced(&self, id: FaceId) -> bool {
        let actions = self.lock().get(&id).map(|held| Arc::clone(&held.actions));
        match actions {
            Some(actions) => {
                actions.close_for_replacement();
                true
            }
            None => false,
        }
    }

    /// The sessions held that have not been ordered closed: the ones the router is keeping.
    pub fn live(&self) -> usize {
        self.lock().values().filter(|held| !held.shedding).count()
    }

    /// Choose the newest sessions to close, until `keep` of the sessions held are being kept, and
    /// mark them: a session already marked is not counted among those kept and is not chosen
    /// again, so asking twice for the same `keep` chooses nothing the second time. Nothing has
    /// been done to the sessions yet; the batch does it ([`ShedBatch::stop_keepalives`],
    /// [`ShedBatch::close`]), outside the registry's lock, because the router's loop registers and
    /// deregisters sessions through it and closing a thousand sessions on a host that is short of
    /// CPU takes longer than the loop can wait.
    pub fn begin_shed(&self, keep: usize) -> ShedBatch {
        let victims: Vec<Arc<SessionLinkActions>> = {
            let mut held = self.lock();
            let live = held.values().filter(|held| !held.shedding).count();
            if live <= keep {
                Vec::new()
            } else {
                // Ids are given in the order sessions were accepted and never reused, so the
                // highest are the newest, and the map is ordered by them.
                held.values_mut()
                    .rev()
                    .filter(|held| !held.shedding)
                    .take(live - keep)
                    .map(|session| {
                        session.shedding = true;
                        Arc::clone(&session.actions)
                    })
                    .collect()
            }
        };
        self.shed
            .fetch_add(victims.len(), std::sync::atomic::Ordering::Relaxed);
        ShedBatch { victims }
    }

    /// Order the newest sessions closed until `keep` of the sessions held are being kept, and
    /// return how many were ordered closed now: [`Self::begin_shed`] and the whole of the batch.
    pub fn shed_newest(&self, keep: usize) -> usize {
        let batch = self.begin_shed(keep);
        let ordered = batch.len();
        batch.stop_keepalives();
        batch.close();
        ordered
    }

    /// Sessions ordered closed for capacity since the router started.
    pub fn total(&self) -> usize {
        self.shed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The sessions [`ShedRegistry::begin_shed`] chose, marked and not yet closed.
///
/// In two steps, because what each costs differs by a factor of fifty and the load the cut is
/// meant to take off is the cheaper one's: the keepalives of every session stop first, which is a
/// lock each, and the closes follow, which are a write each. A node that does the writes first
/// has the load on it for as long as they take (measured: fourteen seconds, for 963 sessions, on a
/// share a fifth of what was declared).
pub struct ShedBatch {
    victims: Vec<Arc<SessionLinkActions>>,
}

impl ShedBatch {
    /// How many sessions the batch holds.
    pub fn len(&self) -> usize {
        self.victims.len()
    }

    /// Whether the batch holds none.
    pub fn is_empty(&self) -> bool {
        self.victims.is_empty()
    }

    /// Stop the keepalives of every session of the batch, now.
    pub fn stop_keepalives(&self) {
        for session in &self.victims {
            session.stop_keepalives();
        }
    }

    /// Tell every peer of the batch and ask every machine to take its session down.
    pub fn close(self) {
        for session in &self.victims {
            session.close_for_capacity();
        }
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node's links to each remote node, from the moment the handshake names the remote until the
//! link is gone: the table behind [`wz_session_core::link_admission::LinkAdmission`], on this
//! runtime's lock.
//!
//! The table and its rule (an established link keeps its place; of two links still in their
//! handshake the one the lower zid dialled is kept) are `wz-session-core`'s
//! ([`wz_session_core::link_admission::LinkBook`]), written once so that the cooperative engine
//! asks the same table. What this runtime adds is the lock: the node's loops run on several
//! threads, and the table is taken under a `std::sync::Mutex`.

/// A node's link admission on the tokio runtime. One per node, shared by every loop that opens a
/// link of it.
pub type LinkRegistry =
    wz_session_core::link_admission::LinkRegistry<crate::runtime_impl::TokioRuntime>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wz_session_core::link_admission::LinkAdmission;

    use super::LinkRegistry;

    const LOW: [u8; 2] = [0x01, 0x00];
    const HIGH: [u8; 2] = [0x02, 0x00];

    /// The rule is `LinkBook`'s and is tested there; this holds the lock's side of it: the loops
    /// of one node are on several threads, and a table shared among them admits one of two links
    /// to a node that race for it, not both and not neither.
    #[test]
    fn links_to_one_node_that_race_for_it_admit_exactly_one() {
        for _ in 0..200 {
            let node = Arc::new(LinkRegistry::new(&LOW));
            let racers: Vec<_> = (0..4)
                .map(|_| {
                    let node = Arc::clone(&node);
                    std::thread::spawn(move || {
                        let link = node.open(false);
                        node.reserve(link, &HIGH)
                    })
                })
                .collect();
            let admitted = racers
                .into_iter()
                .map(|racer| racer.join().expect("a racer does not panic"))
                .filter(|admitted| *admitted)
                .count();
            assert_eq!(admitted, 1, "four inbound links to one node: one is kept");
            assert_eq!(node.len(), 4, "every link holds a row until it is released");
        }
    }
}

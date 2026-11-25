// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which builds hold the staged handshake extension chains (`ext_chain`): the four per-role
//! chains of a session, their fixed form, and everything that stages into or reads them. The build
//! script compiles this file and sets the cfg `wz_ext_chains` from it, which every one of those
//! items reads; the crate compiles it only for its tests.
//!
//! A heap chain is a `Vec` a host may hand over whole (`set_ext_chain`), so every build with the
//! heap storage holds the chains. A fixed chain is only read by the Init and Open body encoders and
//! only filled by a stager: a fixed-storage build holds the chains when it writes one of those
//! bodies and something stages into them, which is the send that is not lend-only, the accepting
//! role (the negotiated patch level) or an extension a handshake action adds. Holding them where
//! nothing reads them leaves a field, its initialiser and its accessor that no build path reaches.

/// The features of a build that decide whether it holds the chains.
pub(crate) struct ExtChainFeatures {
    /// `session-fixed-storage`
    pub(crate) fixed_storage: bool,
    /// `tx-lend-only`
    pub(crate) tx_lend_only: bool,
    /// `session-unicast-accept`
    pub(crate) unicast_accept: bool,
    /// `transport-qos`
    pub(crate) qos: bool,
    /// `session-extshm`
    pub(crate) extshm: bool,
    /// `session-extauth`
    pub(crate) extauth: bool,
    /// `transport-multilink`
    pub(crate) multilink: bool,
    /// `transport-lowlatency`
    pub(crate) lowlatency: bool,
    /// `session-extcompression`
    pub(crate) extcompression: bool,
    /// `codec-init-body`
    pub(crate) init_body: bool,
    /// `codec-open-body`
    pub(crate) open_body: bool,
}

impl ExtChainFeatures {
    /// Whether the build holds the chains: the value of the cfg `wz_ext_chains`.
    pub(crate) fn holds_chains(&self) -> bool {
        if !self.fixed_storage {
            return true;
        }
        let stages = !self.tx_lend_only
            || self.unicast_accept
            || self.qos
            || self.extshm
            || self.extauth
            || self.multilink
            || self.lowlatency
            || self.extcompression;
        let reads = self.init_body || self.open_body;
        stages && reads
    }
}

#[cfg(test)]
mod tests {
    use super::ExtChainFeatures;

    /// A fixed-storage, lend-only build with nothing staged and no body written.
    fn bare_fixed() -> ExtChainFeatures {
        ExtChainFeatures {
            fixed_storage: true,
            tx_lend_only: true,
            unicast_accept: false,
            qos: false,
            extshm: false,
            extauth: false,
            multilink: false,
            lowlatency: false,
            extcompression: false,
            init_body: false,
            open_body: false,
        }
    }

    #[test]
    fn this_build_sets_the_cfg_the_rule_gives_for_its_features() {
        let build = ExtChainFeatures {
            fixed_storage: cfg!(feature = "session-fixed-storage"),
            tx_lend_only: cfg!(feature = "tx-lend-only"),
            unicast_accept: cfg!(feature = "session-unicast-accept"),
            qos: cfg!(feature = "transport-qos"),
            extshm: cfg!(feature = "session-extshm"),
            extauth: cfg!(feature = "session-extauth"),
            multilink: cfg!(feature = "transport-multilink"),
            lowlatency: cfg!(feature = "transport-lowlatency"),
            extcompression: cfg!(feature = "session-extcompression"),
            init_body: cfg!(feature = "codec-init-body"),
            open_body: cfg!(feature = "codec-open-body"),
        };
        assert_eq!(cfg!(wz_ext_chains), build.holds_chains());
    }

    #[test]
    fn a_heap_build_holds_the_chains_whatever_else_it_has() {
        let heap = ExtChainFeatures {
            fixed_storage: false,
            ..bare_fixed()
        };
        assert!(heap.holds_chains());
    }

    #[test]
    fn a_fixed_build_that_writes_no_handshake_body_holds_none() {
        // The accepting role stages the patch level, but nothing would read the chain it went on.
        let acceptor = ExtChainFeatures {
            unicast_accept: true,
            ..bare_fixed()
        };
        assert!(!acceptor.holds_chains());
        let owned_send = ExtChainFeatures {
            tx_lend_only: false,
            ..bare_fixed()
        };
        assert!(!owned_send.holds_chains());
    }

    #[test]
    fn a_fixed_build_that_stages_nothing_holds_none() {
        let both_bodies = ExtChainFeatures {
            init_body: true,
            open_body: true,
            ..bare_fixed()
        };
        assert!(!both_bodies.holds_chains());
    }

    #[test]
    fn a_fixed_build_holds_them_when_a_stager_meets_a_body() {
        let stagers: [fn(&mut ExtChainFeatures); 8] = [
            |f| f.tx_lend_only = false,
            |f| f.unicast_accept = true,
            |f| f.qos = true,
            |f| f.extshm = true,
            |f| f.extauth = true,
            |f| f.multilink = true,
            |f| f.lowlatency = true,
            |f| f.extcompression = true,
        ];
        for stager in stagers {
            for (init_body, open_body) in [(true, false), (false, true)] {
                let mut build = ExtChainFeatures {
                    init_body,
                    open_body,
                    ..bare_fixed()
                };
                stager(&mut build);
                assert!(build.holds_chains());
            }
        }
    }
}

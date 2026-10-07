// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The PHY, through IEEE 802.3 clause 22: find it, reset it, negotiate, read the
//! result.
//!
//! Only STANDARD registers are used (BMCR, BMSR, the two identifier words, ANAR,
//! ANLPAR), so this works for any clause 22 PHY a board puts on the management
//! bus and carries no vendor register, no vendor identifier and no vendor
//! address. The address is FOUND by scanning, or given by the board; it is never
//! written down here, because a board's PHY address is a strap on its schematic,
//! and a guess that happens to be right on one board is wrong on the next.
//!
//! The logic is generic over [`Mdio`], so it runs on the host against a PHY
//! model and on the chip through the MAC's management port.

/// A clause 22 management access failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdioError {
    /// The controller's management shift register never went idle.
    Timeout,
}

/// Why bringing the link up failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// A management access failed.
    Mdio(MdioError),
    /// No address on the bus answered with a plausible identifier.
    NoPhy,
    /// The PHY did not finish its reset in time.
    ResetTimeout,
    /// Auto-negotiation did not bring a link up inside the budget.
    NoLink,
    /// A link is up but the abilities the two ends advertised have nothing in
    /// common (a partner that does not negotiate, found by parallel detection):
    /// the speed and duplex are then vendor-register knowledge this driver does
    /// not have, and guessing would put a wrong speed on the wire.
    UnresolvedMode,
}

impl From<MdioError> for LinkError {
    fn from(e: MdioError) -> Self {
        LinkError::Mdio(e)
    }
}

/// The management bus the PHY sits on, and a way to wait.
pub trait Mdio {
    /// Read register `reg` of the PHY at `phy`.
    fn mdio_read(&mut self, phy: u8, reg: u8) -> Result<u16, MdioError>;
    /// Write `value` to register `reg` of the PHY at `phy`.
    fn mdio_write(&mut self, phy: u8, reg: u8, value: u16) -> Result<(), MdioError>;
    /// Wait about `us` microseconds.
    fn delay_us(&mut self, us: u32);
}

/// The standard clause 22 registers.
pub mod reg {
    pub const BMCR: u8 = 0;
    pub const BMSR: u8 = 1;
    pub const PHYIDR1: u8 = 2;
    pub const PHYIDR2: u8 = 3;
    pub const ANAR: u8 = 4;
    pub const ANLPAR: u8 = 5;
}

const BMCR_RESET: u16 = 1 << 15;
const BMCR_AUTONEG_ENABLE: u16 = 1 << 12;
const BMCR_RESTART_AUTONEG: u16 = 1 << 9;
const BMSR_AUTONEG_COMPLETE: u16 = 1 << 5;
const BMSR_LINK_UP: u16 = 1 << 2;

/// ANAR and ANLPAR share their ability bits.
const ABILITY_10_HALF: u16 = 1 << 5;
const ABILITY_10_FULL: u16 = 1 << 6;
const ABILITY_100_HALF: u16 = 1 << 7;
const ABILITY_100_FULL: u16 = 1 << 8;

/// How long a reset may take: IEEE 802.3 allows 0.5 s.
const RESET_BUDGET_US: u32 = 500_000;
const RESET_POLL_US: u32 = 1_000;
/// How often negotiation is asked whether it finished.
const NEGOTIATION_POLL_US: u32 = 10_000;

/// A speed and duplex, as negotiation resolved them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkMode {
    /// 100 Mbps when true, 10 Mbps when false.
    pub speed_100: bool,
    pub full_duplex: bool,
}

/// The mode two sets of advertised abilities resolve to, by IEEE 802.3's
/// priority (100 full, 100 half, 10 full, 10 half), or `None` when they share
/// none.
pub fn resolve(ours: u16, theirs: u16) -> Option<LinkMode> {
    let common = ours & theirs;
    [
        (ABILITY_100_FULL, true, true),
        (ABILITY_100_HALF, true, false),
        (ABILITY_10_FULL, false, true),
        (ABILITY_10_HALF, false, false),
    ]
    .into_iter()
    .find(|(bit, _, _)| common & bit != 0)
    .map(|(_, speed_100, full_duplex)| LinkMode {
        speed_100,
        full_duplex,
    })
}

/// The address of the first PHY that answers, or `None`.
///
/// A PHY is present when its two identifier words are neither all ones (an idle
/// bus with its pull-up) nor all zeros (a stuck-low bus). No identifier value is
/// compared against: any clause 22 PHY has an identifier, and a board has one.
pub fn find<M: Mdio>(bus: &mut M) -> Result<Option<u8>, MdioError> {
    for phy in 0..32u8 {
        let id1 = bus.mdio_read(phy, reg::PHYIDR1)?;
        let id2 = bus.mdio_read(phy, reg::PHYIDR2)?;
        let silent = id1 == 0xFFFF && id2 == 0xFFFF;
        let stuck = id1 == 0 && id2 == 0;
        if !silent && !stuck {
            return Ok(Some(phy));
        }
    }
    Ok(None)
}

/// Software-reset the PHY and wait for the bit to clear.
pub fn reset<M: Mdio>(bus: &mut M, phy: u8) -> Result<(), LinkError> {
    bus.mdio_write(phy, reg::BMCR, BMCR_RESET)?;
    let mut waited = 0;
    while waited < RESET_BUDGET_US {
        bus.delay_us(RESET_POLL_US);
        waited += RESET_POLL_US;
        if bus.mdio_read(phy, reg::BMCR)? & BMCR_RESET == 0 {
            return Ok(());
        }
    }
    Err(LinkError::ResetTimeout)
}

/// Enable auto-negotiation and restart it.
pub fn start_autoneg<M: Mdio>(bus: &mut M, phy: u8) -> Result<(), MdioError> {
    bus.mdio_write(phy, reg::BMCR, BMCR_AUTONEG_ENABLE | BMCR_RESTART_AUTONEG)
}

/// The negotiated mode, or `None` while there is no link or negotiation has not
/// finished.
///
/// BMSR's link bit is latched low (it stays 0 after any loss until read), so it is
/// read twice and the second read is the present state.
pub fn negotiated<M: Mdio>(bus: &mut M, phy: u8) -> Result<Option<LinkMode>, LinkError> {
    let _latched = bus.mdio_read(phy, reg::BMSR)?;
    let status = bus.mdio_read(phy, reg::BMSR)?;
    if status & BMSR_LINK_UP == 0 || status & BMSR_AUTONEG_COMPLETE == 0 {
        return Ok(None);
    }
    let ours = bus.mdio_read(phy, reg::ANAR)?;
    let theirs = bus.mdio_read(phy, reg::ANLPAR)?;
    resolve(ours, theirs)
        .map(Some)
        .ok_or(LinkError::UnresolvedMode)
}

/// Wait up to `budget_us` for negotiation to bring a link up.
pub fn wait_for_link<M: Mdio>(bus: &mut M, phy: u8, budget_us: u32) -> Result<LinkMode, LinkError> {
    let mut waited = 0;
    loop {
        if let Some(mode) = negotiated(bus, phy)? {
            return Ok(mode);
        }
        if waited >= budget_us {
            return Err(LinkError::NoLink);
        }
        bus.delay_us(NEGOTIATION_POLL_US);
        waited += NEGOTIATION_POLL_US;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PHY (or none) at one address of a clause 22 bus, registers as plain
    /// words, with BMSR latched low the way the standard says.
    struct Bus {
        phy: Option<u8>,
        regs: [u16; 32],
        latched_down: bool,
        link: bool,
        resets_to_clear: u32,
        waited_us: u32,
        reads: u32,
    }

    impl Bus {
        fn with_phy(addr: u8) -> Self {
            let mut regs = [0u16; 32];
            regs[reg::PHYIDR1 as usize] = 0x2000;
            regs[reg::PHYIDR2 as usize] = 0x1234;
            regs[reg::ANAR as usize] =
                ABILITY_100_FULL | ABILITY_100_HALF | ABILITY_10_FULL | ABILITY_10_HALF;
            Self {
                phy: Some(addr),
                regs,
                latched_down: false,
                link: false,
                resets_to_clear: 0,
                waited_us: 0,
                reads: 0,
            }
        }

        fn empty() -> Self {
            let mut b = Self::with_phy(0);
            b.phy = None;
            b
        }
    }

    impl Mdio for Bus {
        fn mdio_read(&mut self, phy: u8, reg_no: u8) -> Result<u16, MdioError> {
            self.reads += 1;
            if self.phy != Some(phy) {
                return Ok(0xFFFF);
            }
            Ok(match reg_no {
                reg::BMCR if self.resets_to_clear > 0 => {
                    self.resets_to_clear -= 1;
                    BMCR_RESET
                }
                reg::BMSR => {
                    let mut v = 0;
                    if self.link && !self.latched_down {
                        v |= BMSR_LINK_UP | BMSR_AUTONEG_COMPLETE;
                    }
                    // Reading BMSR clears the latch: the next read is current.
                    self.latched_down = false;
                    v
                }
                r => self.regs[r as usize],
            })
        }

        fn mdio_write(&mut self, phy: u8, reg_no: u8, value: u16) -> Result<(), MdioError> {
            if self.phy == Some(phy) {
                // The reset bit is self-clearing: it is never stored, and a test
                // that wants a reset to take time says so with `resets_to_clear`.
                let kept = if reg_no == reg::BMCR {
                    value & !BMCR_RESET
                } else {
                    value
                };
                self.regs[reg_no as usize] = kept;
            }
            Ok(())
        }

        fn delay_us(&mut self, us: u32) {
            self.waited_us += us;
        }
    }

    #[test]
    fn resolution_follows_the_priority_and_refuses_an_empty_overlap() {
        let all = ABILITY_100_FULL | ABILITY_100_HALF | ABILITY_10_FULL | ABILITY_10_HALF;
        assert_eq!(
            resolve(all, all),
            Some(LinkMode {
                speed_100: true,
                full_duplex: true
            })
        );
        assert_eq!(
            resolve(all, ABILITY_100_HALF | ABILITY_10_FULL),
            Some(LinkMode {
                speed_100: true,
                full_duplex: false
            }),
            "100 half outranks 10 full"
        );
        assert_eq!(
            resolve(all, ABILITY_10_FULL | ABILITY_10_HALF),
            Some(LinkMode {
                speed_100: false,
                full_duplex: true
            })
        );
        assert_eq!(
            resolve(ABILITY_100_FULL, ABILITY_10_HALF),
            None,
            "nothing in common is not a mode"
        );
        assert_eq!(resolve(all, 0), None, "a partner that did not negotiate");
    }

    #[test]
    fn the_scan_finds_a_phy_wherever_the_board_strapped_it_and_none_on_an_idle_bus() {
        for addr in [0u8, 1, 7, 31] {
            let mut bus = Bus::with_phy(addr);
            assert_eq!(find(&mut bus), Ok(Some(addr)), "address {addr}");
        }
        assert_eq!(
            find(&mut Bus::empty()),
            Ok(None),
            "an idle bus reads all ones"
        );
        let mut stuck = Bus::with_phy(3);
        stuck.regs[reg::PHYIDR1 as usize] = 0;
        stuck.regs[reg::PHYIDR2 as usize] = 0;
        assert_eq!(
            find(&mut stuck),
            Ok(None),
            "an all-zero identifier is a stuck bus"
        );
    }

    #[test]
    fn a_reset_that_clears_passes_and_one_that_never_clears_times_out() {
        let mut bus = Bus::with_phy(1);
        bus.resets_to_clear = 3;
        assert_eq!(reset(&mut bus, 1), Ok(()));
        assert!(
            bus.waited_us >= 3 * RESET_POLL_US,
            "it waited for the clear"
        );

        let mut stuck = Bus::with_phy(1);
        stuck.resets_to_clear = u32::MAX;
        assert_eq!(reset(&mut stuck, 1), Err(LinkError::ResetTimeout));
    }

    #[test]
    fn negotiation_reports_nothing_until_the_link_is_up_and_then_the_resolved_mode() {
        let mut bus = Bus::with_phy(1);
        bus.regs[reg::ANLPAR as usize] = ABILITY_100_FULL | ABILITY_10_FULL;
        assert_eq!(negotiated(&mut bus, 1), Ok(None), "no link yet");
        assert_eq!(
            bus.reads, 2,
            "the status was read twice and nothing past it while there is no link"
        );
        bus.link = true;
        assert_eq!(
            negotiated(&mut bus, 1),
            Ok(Some(LinkMode {
                speed_100: true,
                full_duplex: true
            }))
        );
        assert_eq!(
            bus.reads,
            2 + 4,
            "with a link it also read our abilities and the partner's"
        );
    }

    #[test]
    fn the_latched_low_link_bit_is_read_past() {
        let mut bus = Bus::with_phy(1);
        bus.regs[reg::ANLPAR as usize] = ABILITY_10_HALF;
        bus.link = true;
        // The link dropped and came back: the first BMSR read still says down.
        bus.latched_down = true;
        assert_eq!(
            negotiated(&mut bus, 1),
            Ok(Some(LinkMode {
                speed_100: false,
                full_duplex: false
            })),
            "the second read is the present state"
        );
        assert!(
            !bus.latched_down,
            "the first status read consumed the latch the double was told to hold"
        );
        assert_eq!(
            bus.reads, 4,
            "two status reads, then our abilities and the partner's"
        );
    }

    #[test]
    fn a_link_with_no_common_ability_is_refused_rather_than_guessed() {
        let mut bus = Bus::with_phy(1);
        bus.link = true;
        bus.regs[reg::ANLPAR as usize] = 0;
        assert_eq!(negotiated(&mut bus, 1), Err(LinkError::UnresolvedMode));
        assert_eq!(
            bus.reads, 4,
            "it read both abilities before it refused, so the refusal is the code's own"
        );
    }

    #[test]
    fn waiting_for_a_link_that_never_comes_gives_up_at_the_budget() {
        let mut bus = Bus::with_phy(1);
        assert_eq!(wait_for_link(&mut bus, 1, 100_000), Err(LinkError::NoLink));
        assert!(bus.waited_us >= 100_000);

        let mut up = Bus::with_phy(1);
        up.link = true;
        up.regs[reg::ANLPAR as usize] = ABILITY_100_HALF;
        assert_eq!(
            wait_for_link(&mut up, 1, 0),
            Ok(LinkMode {
                speed_100: true,
                full_duplex: false
            }),
            "a link already up needs no wait"
        );
    }

    #[test]
    fn autoneg_start_writes_enable_and_restart() {
        let mut bus = Bus::with_phy(2);
        start_autoneg(&mut bus, 2).unwrap();
        assert_eq!(
            bus.regs[reg::BMCR as usize],
            BMCR_AUTONEG_ENABLE | BMCR_RESTART_AUTONEG
        );
    }
}

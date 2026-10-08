// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The crate against the register-level model of the chip in `model.rs`.
//!
//! The register addresses and values the tests expect are written out as literals
//! from the documents (the data sheet DS60001734F, the configuration note AN1760
//! DS60001760G, the errata DS80001075F), not taken from the crate's own `regs`,
//! so a wrong constant in the crate cannot agree with itself. Numbers computed
//! from the note's formulas were worked out by hand and the working is in a
//! comment beside them.

use super::*;
use crate::model::{hash_index, Access, Chip, FCS};
use std::cell::Cell;
use std::vec;
use std::vec::Vec;
use wz_oa_tc6::proto::Reg;
use wz_oa_tc6::Error as BusError;

/// A unicast address (the group bit of the first byte is clear).
const MAC: [u8; 6] = [0x02, 0x00, 0x5E, 0x10, 0x20, 0x30];

/// `DEVID` for `model` at silicon revision `rev`: MODEL in bits 19:4, REV in 3:0.
fn devid(model: u16, rev: u8) -> u32 {
    (u32::from(model) << 4) | u32::from(rev)
}

fn config() -> Config {
    Config {
        mac_address: MAC,
        plca: Plca::Off,
        accept_all_multicast: false,
        accept_newer_revisions: false,
    }
}

fn follower() -> Config {
    Config {
        plca: Plca::Node { id: 5, count: 8 },
        ..config()
    }
}

/// A LAN8650 at revision B0 whose two indirect values (AN1760: the five bits at
/// indirect addresses 0x04 and 0x08) are `raw1` and `raw2`.
fn chip_with(raw1: u16, raw2: u16) -> Chip {
    let mut chip = Chip::new(devid(0x8650, 1));
    chip.indirect.insert(0x04, raw1);
    chip.indirect.insert(0x08, raw2);
    chip
}

fn chip() -> Chip {
    chip_with(0, 0)
}

fn open_chip(chip: Chip, config: &Config) -> Result<Lan865xMac<Chip>, OpenError<()>> {
    let clock = Cell::new(0u64);
    open(
        chip,
        config,
        |us| clock.set(clock.get() + u64::from(us)),
        || clock.get(),
    )
}

fn opened(config: &Config) -> Lan865xMac<Chip> {
    open_chip(chip(), config).unwrap()
}

/// The chip lent to `open`, so a test can look at it after `open` has failed and
/// dropped its SPI master.
struct ByRef<'a>(&'a mut Chip);

impl SpiTransfer for ByRef<'_> {
    type Error = ();

    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), ()> {
        self.0.transfer(tx, rx)
    }
}

fn try_open(chip: &mut Chip, config: &Config) -> Result<(), OpenError<()>> {
    let clock = Cell::new(0u64);
    open(
        ByRef(chip),
        config,
        |us| clock.set(clock.get() + u64::from(us)),
        || clock.get(),
    )
    .map(|_| ())
}

fn r(mms: u8, addr: u16) -> Access {
    Access::Read(Reg::new(mms, addr))
}

fn w(mms: u8, addr: u16, value: u32) -> Access {
    Access::Write(Reg::new(mms, addr), value)
}

fn log(mac: &mut Lan865xMac<Chip>) -> Vec<Access> {
    mac.chip().accesses.clone()
}

fn index_of(log: &[Access], what: Access) -> usize {
    log.iter()
        .position(|access| *access == what)
        .unwrap_or_else(|| panic!("{what:?} was never accessed"))
}

/// The accesses that follow the first `start`, as many as `expected` has.
fn window<'a>(log: &'a [Access], start: Access, expected: &[Access]) -> &'a [Access] {
    let at = index_of(log, start);
    &log[at..at + expected.len()]
}

/// AN1760 Table 1, "Configuration register writes", in the order the document
/// prints it, for the two computed parameters given.
fn an1760_table1(cfgparam1: u32, cfgparam2: u32) -> Vec<Access> {
    vec![
        w(4, 0x00D0, 0x3F31),
        w(4, 0x00E0, 0xC000),
        w(4, 0x0084, cfgparam1),
        w(4, 0x008A, cfgparam2),
        w(4, 0x00E9, 0x9E50),
        w(4, 0x00F5, 0x1CF8),
        w(4, 0x00F4, 0xC020),
        w(4, 0x00F8, 0xB900),
        w(4, 0x00F9, 0x4E53),
        w(4, 0x0081, 0x0080),
        w(4, 0x0091, 0x9660),
        w(1, 0x0077, 0x0028),
        w(4, 0x0043, 0x00FF),
        w(4, 0x0044, 0xFFFF),
        w(4, 0x0045, 0x0000),
        w(4, 0x0053, 0x00FF),
        w(4, 0x0054, 0xFFFF),
        w(4, 0x0055, 0x0000),
        w(4, 0x0040, 0x0002),
        w(4, 0x0050, 0x0002),
    ]
}

/// The handshake AN1760 gives for `indirect_read(0x04, ..)` and then
/// `indirect_read(0x08, ..)`.
fn indirect_handshakes() -> Vec<Access> {
    vec![
        w(4, 0x00D8, 0x04),
        w(4, 0x00DA, 0x02),
        r(4, 0x00D9),
        w(4, 0x00D8, 0x08),
        w(4, 0x00DA, 0x02),
        r(4, 0x00D9),
    ]
}

// ---- the model itself -----------------------------------------------------

#[test]
fn the_models_hash_follows_the_data_sheets_function() {
    // DS60001734F 6.4.6: hash_index[k] is the exclusive OR of da[k], da[k+6], ...
    // da[k+42], da[0] the least significant bit of the first byte.
    //
    // 01:00:5E:00:00:FB. Set bits: 0, 17, 18, 19, 20, 22, 40, 41, 43, 44, 45, 46,
    // 47. hash[0] = da0^da18 = 0; hash[1] = da19^da43 = 0; hash[2] = da20^da44 = 0;
    // hash[3] = da45 = 1; hash[4] = da22^da40^da46 = 1; hash[5] = da17^da41^da47 =
    // 1. Index = 8 + 16 + 32 = 56.
    assert_eq!(hash_index(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]), 56);
    // 33:33:00:00:00:01. Set bits: 0, 1, 4, 5, 8, 9, 12, 13, 40. hash[0] =
    // da0^da12 = 0; hash[1] = da1^da13 = 0; hash[2] = da8 = 1; hash[3] = da9 = 1;
    // hash[4] = da4^da40 = 0; hash[5] = da5 = 1. Index = 4 + 8 + 32 = 44.
    assert_eq!(hash_index(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]), 44);
}

// ---- identity -------------------------------------------------------------

#[test]
fn the_product_and_revision_come_from_devid_and_nothing_else() {
    // MODEL is bits 19:4 and REV bits 3:0 (DS60001734F 11.6.6); REV 1 is B0 and 2
    // is B1 (DS80001075F Table 1).
    let part = |product, revision| Ok(Identity { product, revision });
    assert_eq!(identify(0x0008_6501), part(Product::Lan8650, Revision::B0));
    assert_eq!(identify(0x0008_6502), part(Product::Lan8650, Revision::B1));
    assert_eq!(identify(0x0008_6511), part(Product::Lan8651, Revision::B0));
    assert_eq!(identify(0x0008_6512), part(Product::Lan8651, Revision::B1));
    assert_eq!(
        identify(0x0008_6503),
        part(Product::Lan8650, Revision::Newer(3))
    );
    assert_eq!(
        identify(0x0008_650F),
        part(Product::Lan8650, Revision::Newer(15))
    );
    // The bits around the two fields (31:20) do not matter.
    assert_eq!(identify(0xF0F8_6502), part(Product::Lan8650, Revision::B1));

    assert_eq!(
        identify(0x0008_6500),
        Err(IdentityError::UnknownRevision(0))
    );
    assert_eq!(
        identify(0x0008_6521),
        Err(IdentityError::UnknownModel(0x8652))
    );
    assert_eq!(identify(0x0000_0001), Err(IdentityError::UnknownModel(0)));
    assert_eq!(
        identify(0xFFFF_FFFF),
        Err(IdentityError::UnknownModel(0xFFFF))
    );
}

#[test]
fn the_phy_identifier_does_not_identify_the_product() {
    // Errata s1 (DS80001075F 1.1): OA_PHYID reflects the PHY. Its reset value, from
    // DS60001734F 11.1.2 (OUI 00800F, model 011011, revision 0011), is
    // 0x0007_C1B3, and read as a DEVID it is no part this crate drives.
    assert_eq!(
        identify(0x0007_C1B3),
        Err(IdentityError::UnknownModel(0x7C1B))
    );
}

#[test]
fn devid_is_read_before_anything_is_written_and_names_the_part() {
    let mut mac = opened(&config());
    assert_eq!(
        mac.identity(),
        Identity {
            product: Product::Lan8650,
            revision: Revision::B0
        }
    );
    let log = log(&mut mac);
    assert_eq!(log[0], r(10, 0x0094), "the first access of all is DEVID");
    let first_write = log
        .iter()
        .position(|a| matches!(a, Access::Write(..)))
        .unwrap();
    assert!(first_write > 0);
}

/// `open` on a part with this `DEVID` fails as `expected`, having read `DEVID`
/// and written nothing.
fn refuses_part(devid: u32, expected: OpenError<()>) {
    let mut chip = Chip::new(devid);
    assert_eq!(try_open(&mut chip, &config()), Err(expected), "{devid:#x}");
    assert_eq!(chip.accesses, vec![r(10, 0x0094)], "only DEVID was read");
    assert_eq!(chip.resets, 0, "{devid:#x}");
}

#[test]
fn a_model_that_is_not_ours_is_refused_with_nothing_written() {
    refuses_part(
        devid(0x8652, 1),
        OpenError::Identity(IdentityError::UnknownModel(0x8652)),
    );
    // A bus that reads back all ones: no chip, or one that is not answering.
    refuses_part(
        0xFFFF_FFFF,
        OpenError::Identity(IdentityError::UnknownModel(0xFFFF)),
    );
}

#[test]
fn a_revision_no_document_assigns_is_refused_with_nothing_written() {
    refuses_part(
        devid(0x8650, 0),
        OpenError::Identity(IdentityError::UnknownRevision(0)),
    );
}

#[test]
fn a_newer_revision_is_refused_by_default_with_nothing_written() {
    refuses_part(
        devid(0x8651, 3),
        OpenError::RevisionNotAccepted(Identity {
            product: Product::Lan8651,
            revision: Revision::Newer(3),
        }),
    );
}

#[test]
fn a_newer_revision_is_driven_only_when_the_config_accepts_it() {
    let mut chip = chip_with(0, 0);
    chip.devid = devid(0x8651, 3);
    let accepting = Config {
        accept_newer_revisions: true,
        ..config()
    };
    let mac = open_chip(chip, &accepting).unwrap();
    assert_eq!(
        mac.identity(),
        Identity {
            product: Product::Lan8651,
            revision: Revision::Newer(3)
        }
    );
}

// ---- the config -----------------------------------------------------------

/// `bad` is refused as `expected` by `validate` and by `open`, and `open` does it
/// before any bus traffic.
fn refuses_config(bad: Config, expected: ConfigError) {
    assert_eq!(bad.validate(), Err(expected));
    let mut chip = chip();
    assert_eq!(try_open(&mut chip, &bad), Err(OpenError::Config(expected)));
    assert_eq!(chip.transfers, 0, "{bad:?} reached the bus");
}

#[test]
fn a_group_address_is_refused_as_the_station_address_before_the_bus_is_touched() {
    refuses_config(
        Config {
            mac_address: [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB],
            ..config()
        },
        ConfigError::MacAddressIsGroup,
    );
    refuses_config(
        Config {
            mac_address: [0xFF; 6],
            ..config()
        },
        ConfigError::MacAddressIsGroup,
    );
}

#[test]
fn the_zero_address_is_refused_before_the_bus_is_touched() {
    refuses_config(
        Config {
            mac_address: [0; 6],
            ..config()
        },
        ConfigError::MacAddressIsZero,
    );
}

#[test]
fn a_plca_id_of_0xff_is_refused_before_the_bus_is_touched() {
    // 0xFF disables PLCA (DS60001734F 11.5.59), which `Plca::Off` asks for.
    refuses_config(
        Config {
            plca: Plca::Node { id: 0xFF, count: 8 },
            ..config()
        },
        ConfigError::PlcaIdDisablesPlca,
    );
}

#[test]
fn a_coordinator_without_transmit_opportunities_is_refused_before_the_bus_is_touched() {
    refuses_config(
        Config {
            plca: Plca::Node { id: 0, count: 0 },
            ..config()
        },
        ConfigError::PlcaCoordinatorNeedsCount,
    );
}

#[test]
fn the_edges_of_a_valid_plca_config_are_accepted() {
    for plca in [
        Plca::Off,
        Plca::Node { id: 0, count: 1 },
        Plca::Node { id: 0, count: 255 },
        Plca::Node { id: 1, count: 0 },
        Plca::Node {
            id: 0xFE,
            count: 255,
        },
    ] {
        let c = Config { plca, ..config() };
        assert_eq!(c.validate(), Ok(()), "{plca:?}");
        let mut chip = chip();
        assert_eq!(try_open(&mut chip, &c), Ok(()), "{plca:?}");
    }
}

// ---- the reset ------------------------------------------------------------

#[test]
fn the_power_on_reset_flag_is_cleared_before_the_soft_reset_is_issued() {
    // Power-on leaves RESETC set until the host clears it (DS60001734F 4.1.1.1),
    // so a reset whose completion is "RESETC is set" needs the old one gone first.
    // The data sheet gives no reset duration, so only the order can be checked.
    let mut mac = opened(&config());
    let log = log(&mut mac);
    let devid = index_of(&log, r(10, 0x0094));
    let clear = index_of(&log, w(0, 0x0008, 1 << 6));
    let reset = index_of(&log, w(0, 0x0003, 1));
    let first_vendor = log.iter().position(|a| a.reg().mms == 4).unwrap();
    assert!(devid < clear && clear < reset && reset < first_vendor);
    assert_eq!(mac.chip().resets, 1);
}

#[test]
fn a_part_that_never_reports_the_reset_done_fails_the_open_at_the_budget() {
    let mut chip = chip();
    chip.reset_never_completes = true;
    let clock = Cell::new(0u64);
    let result = open(
        ByRef(&mut chip),
        &config(),
        |us| clock.set(clock.get() + u64::from(us)),
        || clock.get(),
    )
    .map(|_| ());
    assert_eq!(result, Err(OpenError::Bus(BusError::ResetTimeout)));
    assert!(clock.get() >= 100_000, "the budget is 100 ms of clock");
    assert!(
        !chip
            .accesses
            .iter()
            .any(|a| matches!(a, Access::Write(reg, _) if reg.mms == 1 || reg.mms == 4)),
        "nothing was configured on a part that did not reset"
    );
}

// ---- the vendor configuration (AN1760) -------------------------------------

#[test]
fn the_indirect_reads_use_the_documented_handshake_and_come_first() {
    let mut mac = opened(&config());
    let log = log(&mut mac);
    let handshakes = indirect_handshakes();
    let first_vendor = log.iter().position(|a| a.reg().mms == 4).unwrap();
    assert_eq!(&log[first_vendor..first_vendor + 6], &handshakes[..]);
}

#[test]
fn table_1_is_written_in_the_documents_order_straight_after_the_reads() {
    // Offsets 0 and 0: cfgparam1 = (9 << 10) | (14 << 4) | 3 = 0x2400 | 0xE0 | 3 =
    // 0x24E3 and cfgparam2 = 40 << 10 = 0xA000.
    let mut mac = open_chip(chip_with(0, 0), &config()).unwrap();
    let log = log(&mut mac);
    let table = an1760_table1(0x24E3, 0xA000);
    let after_reads = index_of(&log, w(4, 0x00D0, 0x3F31));
    assert_eq!(
        &log[after_reads - 1],
        &r(4, 0x00D9),
        "right after the reads"
    );
    assert_eq!(&log[after_reads..after_reads + table.len()], &table[..]);
}

#[test]
fn the_computed_parameters_follow_the_notes_arithmetic_for_several_offsets() {
    // (value1, value2, cfgparam1, cfgparam2); each value is the five bits the
    // note reads, signed with bit 4 as the sign (AN1760, "Calculation of
    // configuration parameters"), and the parameters are worked out by hand:
    //
    //   +5, -5:   cfgparam1 = (14 << 10) | (19 << 4) | 3 = 0x3800 | 0x130 | 3
    //             cfgparam2 = (40 - 5) << 10 = 35 << 10 = 0x8C00
    //   -5, +7:   cfgparam1 = (4 << 10) | (9 << 4) | 3 = 0x1000 | 0x90 | 3
    //             cfgparam2 = 47 << 10 = 0xBC00
    //   -16, +15: cfgparam1 = ((9-16) & 0x3F = 57) << 10 | ((14-16) & 0x3F = 62) << 4 | 3
    //                       = 0xE400 | 0x3E0 | 3
    //             cfgparam2 = 55 << 10 = 0xDC00
    //   +15, -16: cfgparam1 = (24 << 10) | (29 << 4) | 3 = 0x6000 | 0x1D0 | 3
    //             cfgparam2 = 24 << 10 = 0x6000
    //   -1, -1:   cfgparam1 = (8 << 10) | (13 << 4) | 3 = 0x2000 | 0xD0 | 3
    //             cfgparam2 = 39 << 10 = 0x9C00
    //   -10, 0:   cfgparam1 = ((9-10) & 0x3F = 63) << 10 | (4 << 4) | 3
    //                       = 0xFC00 | 0x40 | 3
    let cases: [(u16, u16, u32, u32); 7] = [
        (0x00, 0x00, 0x24E3, 0xA000),
        (0x05, 0x1B, 0x3933, 0x8C00),
        (0x1B, 0x07, 0x1093, 0xBC00),
        (0x10, 0x0F, 0xE7E3, 0xDC00),
        (0x0F, 0x10, 0x61D3, 0x6000),
        (0x1F, 0x1F, 0x20D3, 0x9C00),
        (0x16, 0x00, 0xFC43, 0xA000),
    ];
    for (value1, value2, cfgparam1, cfgparam2) in cases {
        let mut mac = open_chip(chip_with(value1, value2), &config()).unwrap();
        let log = log(&mut mac);
        let written = |reg: Reg| -> Vec<u32> {
            log.iter()
                .filter_map(|a| match a {
                    Access::Write(at, v) if *at == reg => Some(*v),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            written(Reg::new(4, 0x0084)),
            vec![cfgparam1],
            "cfgparam1 for values {value1:#x}, {value2:#x}"
        );
        assert_eq!(
            written(Reg::new(4, 0x008A)),
            vec![cfgparam2],
            "cfgparam2 for values {value1:#x}, {value2:#x}"
        );
    }
}

#[test]
fn the_arithmetic_of_the_note_on_its_own() {
    assert_eq!(an1760::signed5(0x00), 0);
    assert_eq!(an1760::signed5(0x0F), 15);
    assert_eq!(an1760::signed5(0x10), -16);
    assert_eq!(an1760::signed5(0x1B), -5);
    assert_eq!(an1760::signed5(0x1F), -1);
    assert_eq!(an1760::cfgparam1(0), 0x24E3);
    assert_eq!(an1760::cfgparam1(-5), 0x1093);
    assert_eq!(an1760::cfgparam1(15), 0x61D3);
    assert_eq!(an1760::cfgparam1(-16), 0xE7E3);
    assert_eq!(an1760::cfgparam2(0), 0xA000);
    assert_eq!(an1760::cfgparam2(-5), 0x8C00);
    assert_eq!(an1760::cfgparam2(15), 0xDC00);
}

#[test]
fn a_register_with_bits_above_the_five_is_masked_to_them() {
    // The model sets the bits above the five in every indirect read (as AN1760's
    // mask suggests they can be); with value 0x05 the offset is +5, not whatever
    // the junk makes of an int8 cast.
    let mut mac = open_chip(chip_with(0x05, 0x05), &config()).unwrap();
    let log = log(&mut mac);
    assert!(log.contains(&w(4, 0x0084, 0x3933)));
    // (40 + 5) << 10 = 45 << 10 = 0xB400.
    assert!(log.contains(&w(4, 0x008A, 0xB400)));
}

// ---- PLCA -------------------------------------------------------------------

#[test]
fn plca_off_writes_nothing_for_plca() {
    let mut mac = opened(&config());
    let log = log(&mut mac);
    assert!(!log.iter().any(|a| {
        let reg = a.reg();
        reg.mms == 4 && (reg.addr == 0xCA01 || reg.addr == 0xCA02 || reg.addr == 0x0087)
    }));
    // The part is still in the state it resets to: ID 0xFF, collision detection on.
    assert_eq!(mac.chip().get(Reg::new(4, 0xCA02)), 0x08FF);
    assert_eq!(mac.chip().get(Reg::new(4, 0x0087)), 0x80C3);
}

#[test]
fn a_coordinator_writes_its_count_in_the_high_byte() {
    // AN1760: plcaparam1 = Node_Count << 8 for Node_ID 0. CDCTL0 resets to 0x80C3
    // (DS60001734F 11.5.51) and CDEN is bit 15, so the read-modify-write leaves
    // 0x00C3 behind.
    let expected = [
        w(4, 0xCA02, 0x0800),
        w(4, 0xCA01, 0x8000),
        r(4, 0x0087),
        w(4, 0x0087, 0x00C3),
    ];
    let c = Config {
        plca: Plca::Node { id: 0, count: 8 },
        ..config()
    };
    let mut mac = opened(&c);
    let log = log(&mut mac);
    assert_eq!(window(&log, expected[0], &expected), &expected[..]);

    let c = Config {
        plca: Plca::Node { id: 0, count: 255 },
        ..config()
    };
    let mut mac = opened(&c);
    assert!(mac.chip().accesses.contains(&w(4, 0xCA02, 0xFF00)));
}

#[test]
fn a_follower_writes_its_id_alone() {
    // AN1760: plcaparam1 = Node_ID for a follower, and the count is not written.
    let expected = [
        w(4, 0xCA02, 0x0005),
        w(4, 0xCA01, 0x8000),
        r(4, 0x0087),
        w(4, 0x0087, 0x00C3),
    ];
    let mut mac = opened(&follower());
    let log = log(&mut mac);
    assert_eq!(window(&log, expected[0], &expected), &expected[..]);

    let c = Config {
        plca: Plca::Node { id: 0xFE, count: 8 },
        ..config()
    };
    let mut mac = opened(&c);
    assert!(mac.chip().accesses.contains(&w(4, 0xCA02, 0x00FE)));
}

#[test]
fn plca_is_set_up_right_after_table_1_and_before_the_mac() {
    let mut mac = opened(&follower());
    let log = log(&mut mac);
    let table_end = index_of(&log, w(4, 0x0050, 0x0002));
    assert_eq!(log[table_end + 1], w(4, 0xCA02, 0x0005));
    let first_mac = log
        .iter()
        .position(|a| a.reg().mms == 1 && a.reg() != Reg::new(1, 0x0077))
        .unwrap();
    assert!(first_mac > index_of(&log, w(4, 0x0087, 0x00C3)));
}

// ---- the MAC ------------------------------------------------------------------

#[test]
fn the_address_words_match_the_data_sheets_example() {
    // DS60001734F 6.4.4 and 6.5.1.2: 21:43:65:87:A9:CB is MAC_SAB1 0x8765_4321 and
    // MAC_SAT1 0x0000_CBA9. (That address has the group bit set, so it is the
    // example of the register layout and not an address `open` accepts.)
    assert_eq!(
        config::address_words([0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB]),
        (0x8765_4321, 0x0000_CBA9)
    );
}

#[test]
fn the_bottom_address_register_is_written_before_the_top_and_the_address_ends_up_active() {
    // MAC = 02:00:5E:10:20:30: bytes 0..3 little-endian are 0x105E_0002 and bytes
    // 4 and 5 are 0x3020.
    let mut mac = opened(&config());
    let log = log(&mut mac);
    let bottom = index_of(&log, w(1, 0x0022, 0x105E_0002));
    let top = index_of(&log, w(1, 0x0023, 0x0000_3020));
    assert!(bottom < top, "writing the top half is what activates it");
    let last_filter_write = log
        .iter()
        .rposition(|a| a.reg().mms == 1 && a.reg().addr != 0 && matches!(a, Access::Write(..)))
        .unwrap();
    assert_eq!(
        last_filter_write, top,
        "the address is the last filter write"
    );
    assert!(mac.chip().address1_active());
    assert_eq!(mac.chip().address1(), MAC);
}

#[test]
fn received_frames_carry_no_fcs() {
    // MAC_NCFGR resets to 0x0008_0000 (a reserved bit at 19 is 1), and RFCS is bit
    // 17: the reserved bit has to survive.
    let mut mac = opened(&config());
    let log = log(&mut mac);
    assert_eq!(
        window(
            &log,
            r(1, 0x0001),
            &[r(1, 0x0001), w(1, 0x0001, 0x000A_0000)]
        ),
        &[r(1, 0x0001), w(1, 0x0001, 0x000A_0000)][..]
    );

    let mut frame = MAC.to_vec();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 9, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(mac.chip().network_frame(&frame));
    let mut out = [0u8; 256];
    let got = mac.receive(&mut out).expect("the frame");
    assert_eq!(&out[..got], &frame[..], "no FCS after the payload");

    // CONTROL: the same part with RFCS clear hands the host the FCS as well.
    mac.chip().set(Reg::new(1, 0x0001), 0x0008_0000);
    assert!(mac.chip().network_frame(&frame));
    let got = mac.receive(&mut out).expect("the frame");
    assert_eq!(got, frame.len() + FCS.len());
    assert_eq!(&out[got - FCS.len()..got], &FCS[..]);
}

#[test]
fn only_what_is_addressed_to_the_station_is_accepted_without_the_multicast_option() {
    let mut mac = opened(&config());
    assert_eq!(mac.chip().get(Reg::new(1, 0x0001)), 0x000A_0000);
    let body = [0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let to = |da: [u8; 6]| {
        let mut f = da.to_vec();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        f.extend_from_slice(&body);
        f
    };
    assert!(mac.chip().network_frame(&to(MAC)));
    assert!(mac.chip().network_frame(&to([0xFF; 6])), "broadcast");
    assert!(!mac
        .chip()
        .network_frame(&to([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB])));
    assert!(!mac.chip().network_frame(&to([0x33, 0x33, 0, 0, 0, 1])));
    assert!(
        !mac.chip().network_frame(&to([0x02, 0, 0, 0, 0, 0x77])),
        "not ours"
    );
    // The hash registers were left alone.
    assert!(!log(&mut mac)
        .iter()
        .any(|a| matches!(a, Access::Write(reg, _) if reg.mms == 1 && (reg.addr == 0x20 || reg.addr == 0x21))));
}

#[test]
fn accepting_all_multicast_sets_the_hash_to_all_ones_and_enables_multicast_hashing() {
    // DS60001734F 6.4.6: "To receive all multicast frames, the Hash register
    // should be set with all ones and the Multicast Hash Enable bit should be set".
    // MTIHEN is bit 6; 0x000A_0000 | 0x40.
    let c = Config {
        accept_all_multicast: true,
        ..config()
    };
    let mut mac = opened(&c);
    let log = log(&mut mac);
    assert!(log.contains(&w(1, 0x0020, 0xFFFF_FFFF)));
    assert!(log.contains(&w(1, 0x0021, 0xFFFF_FFFF)));
    assert!(log.contains(&w(1, 0x0001, 0x000A_0040)));

    let to = |da: [u8; 6]| {
        let mut f = da.to_vec();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 9, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
        f
    };
    // Two groups the hash function puts at different indices (56 and 44).
    assert!(mac
        .chip()
        .network_frame(&to([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB])));
    assert!(mac.chip().network_frame(&to([0x33, 0x33, 0, 0, 0, 1])));
    assert!(mac.chip().network_frame(&to(MAC)), "and still the station");
}

#[test]
fn the_mac_is_enabled_after_the_configuration_and_sync_is_declared_last() {
    let mut mac = opened(&config());
    let log = log(&mut mac);
    let n = log.len();
    // TXEN | RXEN = 0x0C; then CONFIG0 read-modify-write: BPS 6 (reset), RFA ZARFE
    // (bit 12) and SYNC (bit 15).
    assert_eq!(log[n - 3], w(1, 0x0000, 0x0C));
    assert_eq!(log[n - 2], r(0, 0x0004));
    assert_eq!(log[n - 1], w(0, 0x0004, 0x0000_9006));
    assert!(mac.chip().synced());

    // And the enabled MAC sends: a transmitted frame reaches the wire.
    let frame = vec![0xAB; 60];
    assert!(mac.transmit(&frame));
    assert_eq!(mac.chip().wire, vec![frame]);
    assert_eq!(mac.chip().tx_dropped, 0);
}

#[test]
fn the_station_address_is_the_one_the_config_gave() {
    let mac = opened(&config());
    assert_eq!(mac.mac_address(), MAC);
    assert_eq!(mac.errors(), 0);
}

// ---- the interrupt line ----------------------------------------------------

#[test]
fn a_quiet_interrupt_line_costs_no_exchange() {
    fn quiet() -> bool {
        false
    }
    let mut mac = opened(&config());
    mac.set_interrupt_probe(quiet);
    let before = mac.chip().transfers;
    let mut buf = [0u8; 64];
    assert_eq!(mac.receive(&mut buf), None);
    assert_eq!(mac.chip().transfers, before);
}

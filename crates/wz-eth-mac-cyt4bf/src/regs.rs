// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Register offsets and bit fields of the CYT4BF `MXETH` block.
//!
//! The block is a small wrapper (`CTL`, `STATUS`) in front of a Cadence GEM_GXL
//! whose registers start at `0x1000`. Offsets and positions are the ones
//! Infineon's PDL publishes in `devices/COMPONENT_CAT1C/include/ip/cyip_eth.h`
//! (release-v3.23.0, Apache-2.0); the descriptor words are the layout the PDL's
//! Cadence core driver uses (`drivers/third_party/ethernet/include/edd_int.h`,
//! Apache-2.0). Only what this driver touches is listed, and every name is the
//! PDL's own, lower-cased where Rust asks.

// ---- wrapper -------------------------------------------------------------

/// `ETH.CTL`.
pub const CTL: usize = 0x0000;
/// `CTL.ETH_MODE` position; the field is two bits wide.
pub const CTL_ETH_MODE_POS: u32 = 0;
/// `CTL.ETH_MODE` value for RMII: the PDL's table maps 3 to "RMII - 10/100 Mbps".
pub const CTL_ETH_MODE_RMII: u32 = 3;
/// `CTL.REFCLK_SRC_SEL`: 0 takes the reference clock from the HSIO pin, 1 from
/// the internal PLL (the PDL's `cy_en_ethif_clock_ref_t`).
pub const CTL_REFCLK_SRC_SEL_POS: u32 = 2;
/// `CTL.REFCLK_DIV` position; the divider is the field plus one.
pub const CTL_REFCLK_DIV_POS: u32 = 8;
/// `CTL.ENABLED`: the GEM registers above `0x1000` answer only once it is set.
pub const CTL_ENABLED: u32 = 1 << 31;

// ---- GEM, offsets --------------------------------------------------------

pub const NETWORK_CONTROL: usize = 0x1000;
pub const NETWORK_CONFIG: usize = 0x1004;
pub const NETWORK_STATUS: usize = 0x1008;
pub const DMA_CONFIG: usize = 0x1010;
pub const TRANSMIT_STATUS: usize = 0x1014;
pub const RECEIVE_Q_PTR: usize = 0x1018;
pub const TRANSMIT_Q_PTR: usize = 0x101C;
pub const RECEIVE_STATUS: usize = 0x1020;
pub const INT_STATUS: usize = 0x1024;
pub const INT_DISABLE: usize = 0x102C;
pub const PHY_MANAGEMENT: usize = 0x1034;
pub const HASH_BOTTOM: usize = 0x1080;
pub const HASH_TOP: usize = 0x1084;
pub const SPEC_ADD1_BOTTOM: usize = 0x1088;
pub const SPEC_ADD1_TOP: usize = 0x108C;
/// Transmit queues 1 and 2, and receive queues 1 and 2: the block has three
/// queues each way and this driver uses the first.
pub const TRANSMIT_Q1_PTR: usize = 0x1440;
pub const TRANSMIT_Q2_PTR: usize = 0x1444;
pub const RECEIVE_Q1_PTR: usize = 0x1480;
pub const RECEIVE_Q2_PTR: usize = 0x1484;

// ---- NETWORK_CONTROL -----------------------------------------------------

pub const NWCTRL_ENABLE_RECEIVE: u32 = 1 << 2;
pub const NWCTRL_ENABLE_TRANSMIT: u32 = 1 << 3;
/// The management port (MDIO) is driven only while this is set.
pub const NWCTRL_MAN_PORT_EN: u32 = 1 << 4;
/// Starts the transmit DMA on the descriptors software has released.
pub const NWCTRL_TX_START: u32 = 1 << 9;
/// Halts the transmit DMA after the frame in flight.
pub const NWCTRL_TX_HALT: u32 = 1 << 10;

// ---- NETWORK_CONFIG ------------------------------------------------------

/// Speed select: 1 is 100 Mbps, 0 is 10 Mbps (RMII, no gigabit).
pub const NWCFG_SPEED_100: u32 = 1 << 0;
pub const NWCFG_FULL_DUPLEX: u32 = 1 << 1;
pub const NWCFG_COPY_ALL_FRAMES: u32 = 1 << 4;
pub const NWCFG_MULTICAST_HASH_ENABLE: u32 = 1 << 6;
/// Accept frames up to 1536 bytes: a VLAN-tagged maximum frame is 1522.
pub const NWCFG_RECEIVE_1536: u32 = 1 << 8;
/// Strip the FCS from received frames, which is what `EthernetMac` hands up.
pub const NWCFG_FCS_REMOVE: u32 = 1 << 17;
/// MDC clock divider position; the field is three bits wide.
pub const NWCFG_MDC_DIV_POS: u32 = 18;
/// Data bus width: 0 is 32 bits, which is this block's AHB master.
pub const NWCFG_DATA_BUS_WIDTH_POS: u32 = 21;

// ---- NETWORK_STATUS ------------------------------------------------------

/// The management shift register is idle: the last MDIO operation finished.
pub const NWSR_MAN_DONE: u32 = 1 << 2;

// ---- DMA_CONFIG ----------------------------------------------------------

pub const DMACFG_AMBA_BURST_POS: u32 = 0;
pub const DMACFG_RX_PBUF_SIZE_POS: u32 = 8;
pub const DMACFG_TX_PBUF_SIZE_POS: u32 = 10;
/// Receive buffer size, in units of 64 bytes.
pub const DMACFG_RX_BUF_SIZE_POS: u32 = 16;
pub const DMACFG_FORCE_DISCARD_ON_ERR: u32 = 1 << 24;

// ---- TRANSMIT_STATUS / RECEIVE_STATUS (write one to clear) ----------------

pub const TXSR_USED_BIT_READ: u32 = 1 << 0;
pub const TXSR_COLLISION: u32 = 1 << 1;
pub const TXSR_RETRY_LIMIT_EXCEEDED: u32 = 1 << 2;
pub const TXSR_TRANSMIT_GO: u32 = 1 << 3;
pub const TXSR_AMBA_ERROR: u32 = 1 << 4;
pub const TXSR_TRANSMIT_COMPLETE: u32 = 1 << 5;
pub const TXSR_UNDER_RUN: u32 = 1 << 6;
pub const TXSR_LATE_COLLISION: u32 = 1 << 7;
pub const TXSR_RESP_NOT_OK: u32 = 1 << 8;
/// Every status bit of the register, for clearing.
pub const TXSR_ALL: u32 = 0x1FF;
/// The bits that mean the transmit DMA stopped on an error and the queue has to
/// be re-armed before anything more is sent.
pub const TXSR_FATAL: u32 = TXSR_RETRY_LIMIT_EXCEEDED
    | TXSR_AMBA_ERROR
    | TXSR_UNDER_RUN
    | TXSR_LATE_COLLISION
    | TXSR_RESP_NOT_OK;

pub const RXSR_BUFFER_NOT_AVAILABLE: u32 = 1 << 0;
pub const RXSR_FRAME_RECEIVED: u32 = 1 << 1;
pub const RXSR_OVERRUN: u32 = 1 << 2;
pub const RXSR_RESP_NOT_OK: u32 = 1 << 3;
pub const RXSR_ALL: u32 = 0xF;

// ---- queue pointer registers ---------------------------------------------

/// Bit 0 of a queue pointer register: the queue is disabled. The address is in
/// bits 31:2.
pub const QPTR_DISABLE: u32 = 1 << 0;

// ---- PHY_MANAGEMENT (IEEE 802.3 clause 22 frames) -------------------------

/// The fixed `10` code of a clause 22 frame, at bits 17:16.
pub const MDIO_TURNAROUND: u32 = 2 << 16;
pub const MDIO_REG_POS: u32 = 18;
pub const MDIO_PHY_POS: u32 = 23;
pub const MDIO_OP_POS: u32 = 28;
pub const MDIO_OP_WRITE: u32 = 1;
pub const MDIO_OP_READ: u32 = 2;
/// Start-of-frame for clause 22 (bit 30); clause 45 leaves it clear.
pub const MDIO_START_C22: u32 = 1 << 30;

// ---- descriptors ----------------------------------------------------------

/// Receive word 0: software owns the buffer while this is set (the controller
/// sets it after writing a frame in).
pub const RXD_USED: u32 = 1 << 0;
/// Receive word 0: the last descriptor of the ring.
pub const RXD_WRAP: u32 = 1 << 1;
/// Receive word 0: the buffer address, bits 31:2.
pub const RXD_ADDR_MASK: u32 = 0xFFFF_FFFC;
/// Receive word 1: the frame length, bits 12:0.
pub const RXD_LEN_MASK: u32 = (1 << 13) - 1;
pub const RXD_SOF: u32 = 1 << 14;
pub const RXD_EOF: u32 = 1 << 15;

/// Transmit word 1: the length, bits 13:0.
pub const TXD_LEN_MASK: u32 = (1 << 14) - 1;
/// Transmit word 1: this is the last buffer of the frame.
pub const TXD_LAST: u32 = 1 << 15;
/// Transmit word 1: the last descriptor of the ring.
pub const TXD_WRAP: u32 = 1 << 30;
/// Transmit word 1: software owns the descriptor while this is set (the
/// controller sets it after sending).
pub const TXD_USED: u32 = 1 << 31;

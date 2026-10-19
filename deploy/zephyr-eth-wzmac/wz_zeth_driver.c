/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A Zephyr Ethernet driver for the CYT4BF's ETH0, over wz's `wz-eth-mac-cyt4bf` crate.
 *
 * Zephyr has no driver for this controller. The wz crates have one, which the lwIP backend of
 * the wz admin node drives; this file is the other half of the same seam, so a Zephyr network
 * stack (and a Zephyr application such as zenoh-pico) can sit on the same MAC code. The Rust
 * side is deploy/zephyr-eth-wzmac/zeth_exports.rs (`wz_zeth_*`); this side is an
 * `ethernet_api`, a mutex that serialises every call into the MAC, and a thread that polls it
 * (the crate takes no interrupt).
 *
 * BUILT and unrun on silicon until a lab records a run of it.
 */

#define DT_DRV_COMPAT wz_cyt4bf_eth

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>

#include <ethernet/eth_stats.h>

LOG_MODULE_REGISTER(wz_zeth, CONFIG_NET_L2_ETHERNET_LOG_LEVEL);

/* The Rust side (zeth_exports.rs). */
extern int wz_zeth_open(const uint8_t *address, uint32_t ref_clock_divider,
			uint32_t link_wait_ms);
extern int wz_zeth_transmit(const uint8_t *frame, size_t len);
extern int wz_zeth_receive(uint8_t *buf, size_t capacity);
extern int wz_zeth_poll_link(uint64_t now_ms);
extern int wz_zeth_link_up(void);

/* A frame without its FCS and with room for a VLAN tag; the MAC drops a longer one whole. */
#define ZETH_FRAME_MAX 1536

/* How long a send waits for a free transmit descriptor before it reports the frame lost. */
#define ZETH_TX_WAIT_US 2000
#define ZETH_TX_RETRY_US 20

struct zeth_config {
	struct net_eth_mac_config mac;
	uint32_t ref_clock_divider;
	uint32_t link_wait_ms;
};

struct zeth_data {
	struct net_if *iface;
	uint8_t mac[NET_ETH_ADDR_LEN];
	/* Every call into the MAC after the open is made with this held. */
	struct k_mutex lock;
	struct k_thread rx_thread;
	K_KERNEL_STACK_MEMBER(rx_stack, CONFIG_WZ_ZETH_RX_STACK_SIZE);
	uint8_t rx_frame[ZETH_FRAME_MAX];
	uint8_t tx_frame[ZETH_FRAME_MAX];
	bool carrier;
};

static void zeth_set_carrier(struct zeth_data *data, bool up)
{
	if (data->carrier == up) {
		return;
	}
	data->carrier = up;
	if (up) {
		net_eth_carrier_on(data->iface);
	} else {
		net_eth_carrier_off(data->iface);
	}
}

/* Hand one received frame up. Called without the lock: the allocation may wait on the
 * network stack's pools and the stack may take its time.
 */
static void zeth_deliver(struct zeth_data *data, size_t len)
{
	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(data->iface, len, NET_AF_UNSPEC, 0,
							   K_NO_WAIT);

	if (pkt == NULL) {
		eth_stats_update_errors_rx(data->iface);
		return;
	}
	if (net_pkt_write(pkt, data->rx_frame, len) != 0) {
		net_pkt_unref(pkt);
		eth_stats_update_errors_rx(data->iface);
		return;
	}
	if (net_recv_data(data->iface, pkt) < 0) {
		net_pkt_unref(pkt);
		eth_stats_update_errors_rx(data->iface);
	}
}

static void zeth_rx_thread(void *p1, void *p2, void *p3)
{
	const struct device *dev = p1;
	const struct zeth_config *cfg = dev->config;
	struct zeth_data *data = dev->data;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	/* The open runs here and not in the driver's init: it waits for the PHY and for a link,
	 * which a kernel init level has no business doing. No frame is sent before it is done:
	 * the interface has no carrier until it is.
	 */
	int rc = wz_zeth_open(data->mac, cfg->ref_clock_divider, cfg->link_wait_ms);

	if (rc != 0) {
		LOG_ERR("the MAC did not come up (%d); the interface stays without a carrier", rc);
		return;
	}

	k_mutex_lock(&data->lock, K_FOREVER);
	bool up = wz_zeth_link_up() != 0;

	k_mutex_unlock(&data->lock);
	zeth_set_carrier(data, up);

	/* The open is the deepest this thread goes; say how much of its stack it took, so that a size
	 * that is only just enough does not pass for a size that is.
	 */
	size_t unused = 0;

	if (k_thread_stack_space_get(&data->rx_thread, &unused) == 0) {
		printk("wz: zeth: receive thread stack, %u of %u bytes used by the open\n",
		       (unsigned int)(CONFIG_WZ_ZETH_RX_STACK_SIZE - unused),
		       (unsigned int)CONFIG_WZ_ZETH_RX_STACK_SIZE);
	}

	for (;;) {
		k_mutex_lock(&data->lock, K_FOREVER);
		int len = wz_zeth_receive(data->rx_frame, sizeof(data->rx_frame));

		up = wz_zeth_poll_link((uint64_t)k_uptime_get()) != 0;
		k_mutex_unlock(&data->lock);

		zeth_set_carrier(data, up);
		if (len > 0) {
			zeth_deliver(data, (size_t)len);
			continue;
		}
		if (CONFIG_WZ_ZETH_RX_POLL_INTERVAL_US > 0) {
			k_usleep(CONFIG_WZ_ZETH_RX_POLL_INTERVAL_US);
		} else {
			k_yield();
		}
	}
}

static int zeth_send(const struct device *dev, struct net_pkt *pkt)
{
	struct zeth_data *data = dev->data;
	size_t len = net_pkt_get_len(pkt);

	if (len > sizeof(data->tx_frame)) {
		return -EMSGSIZE;
	}
	/* The stack serialises sends of one interface, so the one buffer is free here. */
	if (net_pkt_read(pkt, data->tx_frame, len) != 0) {
		return -EIO;
	}
	for (uint32_t waited = 0;; waited += ZETH_TX_RETRY_US) {
		k_mutex_lock(&data->lock, K_FOREVER);
		int taken = wz_zeth_transmit(data->tx_frame, len);

		k_mutex_unlock(&data->lock);
		if (taken != 0) {
			return 0;
		}
		if (waited >= ZETH_TX_WAIT_US) {
			eth_stats_update_errors_tx(net_pkt_iface(pkt));
			return -EIO;
		}
		k_busy_wait(ZETH_TX_RETRY_US);
	}
}

static enum ethernet_hw_caps zeth_caps(const struct device *dev, struct net_if *iface)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(iface);
	return ETHERNET_LINK_10BASE | ETHERNET_LINK_100BASE;
}

static void zeth_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct zeth_data *data = dev->data;

	data->iface = iface;
	net_if_set_link_addr(iface, data->mac, sizeof(data->mac), NET_LINK_ETHERNET);
	ethernet_init(iface);
	/* Until the MAC is open and the PHY says so there is no carrier. */
	net_if_carrier_off(iface);

	k_thread_create(&data->rx_thread, data->rx_stack, K_KERNEL_STACK_SIZEOF(data->rx_stack),
			zeth_rx_thread, (void *)dev, NULL, NULL,
			K_PRIO_PREEMPT(CONFIG_WZ_ZETH_RX_PRIORITY), 0, K_NO_WAIT);
	k_thread_name_set(&data->rx_thread, "wz_zeth_rx");
}

static int zeth_init(const struct device *dev)
{
	const struct zeth_config *cfg = dev->config;
	struct zeth_data *data = dev->data;

	k_mutex_init(&data->lock);
	/* The address is the devicetree's (static, or drawn here from the entropy device).
	 * Nothing falls back to a value a build shares: two boards would then both answer to it.
	 */
	if (net_eth_mac_load(&cfg->mac, data->mac) != 0) {
		LOG_ERR("no station address: the node needs `local-mac-address` or "
			"`zephyr,random-mac-address`");
		return -ENODATA;
	}
	return 0;
}

static const struct ethernet_api zeth_api = {
	.iface_api.init = zeth_iface_init,
	.get_capabilities = zeth_caps,
	.send = zeth_send,
};

#define ZETH_DEFINE(inst)                                                                          \
	static const struct zeth_config zeth_config_##inst = {                                     \
		.mac = NET_ETH_MAC_DT_INST_CONFIG_INIT(inst),                                      \
		.ref_clock_divider = DT_INST_PROP(inst, ref_clock_divider),                        \
		.link_wait_ms = DT_INST_PROP(inst, link_wait_ms),                                  \
	};                                                                                         \
	static struct zeth_data zeth_data_##inst;                                                  \
	ETH_NET_DEVICE_DT_INST_DEFINE(inst, zeth_init, NULL, &zeth_data_##inst,                    \
				      &zeth_config_##inst, CONFIG_ETH_INIT_PRIORITY, &zeth_api,    \
				      NET_ETH_MTU)

DT_INST_FOREACH_STATUS_OKAY(ZETH_DEFINE)

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(DT_DRV_COMPAT) <= 1,
	     "the MAC is a single controller: one node, and the Rust side holds one MAC");

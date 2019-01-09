/*
 **************************************************************************
 * Copyright (c) 2018-2019, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_cranipc.c
 *	NSS C-RAN APIs
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include "nss_tx_rx_common.h"

int nss_disable_cran __read_mostly = 0;

module_param(nss_disable_cran, int, S_IRUGO);
MODULE_PARM_DESC(nss_disable_cran, "Disable C-RAN Mode");

extern int nss_cran_mode_enabled;

/*
 * nss_danipc_get_cran_state()
 *	return the C-RAN mode state.
 */
bool nss_cranipc_is_cran_enabled(void)
{
	return nss_cran_mode_enabled;
}
EXPORT_SYMBOL(nss_cranipc_is_cran_enabled);

/*
 * nss_cranipc_verify_ifnum()
 *
 */
static void nss_cranipc_verify_ifnum(uint32_t if_num)
{
	 nss_assert(if_num == NSS_CRANIPC_INTERFACE);
}

/*
 * nss_cranipc_get_context()
 */
struct nss_ctx_instance *nss_cranipc_get_context(void)
{
	return (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.cranipc_handler_id];
}
EXPORT_SYMBOL(nss_cranipc_get_context);

/*
 * nss_cranipc_msg_init()
 *	Initialize the cran message from nlcfg
 */
void nss_cranipc_msg_init(struct nss_cranipc_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
			  nss_cranipc_event_callback_t cb, void *app_data)
{
	nss_cmn_msg_init(&nim->cm, if_num, type, len, (void *)cb, app_data);
}
EXPORT_SYMBOL(nss_cranipc_msg_init);

/*
 * nss_cranipc_msg_handler()
 *	Handle NSS -> HLOS messages for cranipc
 */
static void nss_cranipc_msg_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, void *app_data)
{
	struct nss_cranipc_msg *nvm = (struct nss_cranipc_msg *)ncm;
	nss_cranipc_msg_callback_t cb;

	nss_cranipc_verify_ifnum(ncm->interface);

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncm->type >= NSS_CRANIPC_MSG_TYPE_MAX) {
		nss_warning("%p: received invalid message %d for cranipc interface", nss_ctx, ncm->type);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_cranipc_msg)) {
		nss_warning("%p: length of message is greater than required: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return;
	}

	/*
	 * Update the stats received from NSS-FW
	 */
	if (ncm->type == NSS_CRANIPC_MSG_TYPE_STATS_SYNC) {
		nss_cranipc_sync_update(nss_ctx, &nvm->msg.stats);
		return;
	}

	/*
	 * Update the callback and app_data for NOTIFY messages, cranipc sends all notify messages
	 * to the same callback/app_data.
	 */
	if (ncm->response == NSS_CMM_RESPONSE_NOTIFY) {
		ncm->cb = (nss_ptr_t)nss_ctx->nss_top->cranipc_event_callback;
		ncm->app_data = (nss_ptr_t)app_data;
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Do we have a call back
	 */
	if (!ncm->cb) {
		return;
	}

	/*
	 * callback
	 */
	cb = (nss_cranipc_msg_callback_t)ncm->cb;
	cb((void *)ncm->app_data, nvm);
}

/*
 * nss_cranipc_tx()
 *	Transmit a CRANIPC msg to the firmware.
 */
nss_tx_status_t nss_cranipc_tx(struct nss_ctx_instance *nss_ctx, struct nss_cranipc_msg *msg)
{
	struct nss_cranipc_msg *nm;
	struct sk_buff *nbuf;
	int32_t status;

	nss_info("%p: NSS cranipc Tx\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
			nss_warning("%p: cranipc msg dropped as core not ready", nss_ctx);
			return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]);
		nss_warning("%p: cranipc msg dropped as buffer allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nm = (struct nss_cranipc_msg *)skb_put(nbuf, sizeof(struct nss_cranipc_msg));
	memcpy(nm, msg, sizeof(struct nss_cranipc_msg));

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue cranipc msg\n", nss_ctx);
		return NSS_TX_FAILURE;
	}
	nss_hal_send_interrupt(nss_ctx, NSS_H2N_INTR_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);

	return NSS_TX_SUCCESS;
}
EXPORT_SYMBOL(nss_cranipc_tx);

/*
 * nss_register_cranipc_if()
 */
void *nss_register_cranipc_if(uint32_t if_num, nss_cranipc_callback_t cranipc_cb,
			nss_cranipc_event_callback_t cranipc_ev_cb, struct net_device *netdev)
{
	struct nss_ctx_instance *nss_ctx = nss_cranipc_get_context();
	uint32_t features = 0;

	nss_assert(nss_ctx);
	nss_cranipc_verify_ifnum(if_num);

	nss_ctx->subsys_dp_register[if_num].ndev = netdev;
	nss_ctx->subsys_dp_register[if_num].cb = cranipc_cb;
	nss_ctx->subsys_dp_register[if_num].app_data = NULL;
	nss_ctx->subsys_dp_register[if_num].features = features;

	nss_top_main.cranipc_event_callback = cranipc_ev_cb;

	/*
	 * Return the NSS driver context for CRANIPC.
	 */
	return (void *)nss_ctx;
}
EXPORT_SYMBOL(nss_register_cranipc_if);

/*
 * nss_unregister_cranipc_if()
 */
void nss_unregister_cranipc_if(uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = nss_cranipc_get_context();

	nss_assert(nss_ctx);
	nss_cranipc_verify_ifnum(if_num);

	nss_ctx->subsys_dp_register[if_num].cb = NULL;
	nss_ctx->subsys_dp_register[if_num].ndev = NULL;
	nss_ctx->subsys_dp_register[if_num].app_data = NULL;
	nss_ctx->subsys_dp_register[if_num].features = 0;

	nss_top_main.cranipc_event_callback = NULL;
}
EXPORT_SYMBOL(nss_unregister_cranipc_if);

/*
 * nss_cranipc_register_handler()
 *	debugfs stats msg handler received on static cranipc interface
 */
void nss_cranipc_register_handler(void)
{
	struct nss_ctx_instance *nss_ctx = nss_cranipc_get_context();

	if (nss_disable_cran) {
		nss_info_always("C-RAN disabled through module parameters\n");
		return;
	}

	nss_info("nss_cranipc_register_handler\n");
	nss_core_register_handler(nss_ctx, NSS_CRANIPC_INTERFACE, nss_cranipc_msg_handler, NULL);

	/*
	 * If jumbo_mru is non zero, skip setting it to default.
	 */
	if (!nss_core_get_jumbo_mru())
		nss_core_set_jumbo_mru(NSS_CRANIPC_JUMBO_MRU_DEFAULT);

	/* If user has configured jumbo_mru through sysctl, then also we will enable cran mode */
	nss_cran_mode_enabled = 1;
	nss_info_always("C-RAN is enabled. jumbo_mru set to %d\n", nss_core_get_jumbo_mru());
}
EXPORT_SYMBOL(nss_cranipc_register_handler);

/*
 * nss_cranipc_sync_update()
 *	Update cranipc stats.
 */
void nss_cranipc_sync_update(struct nss_ctx_instance *nss_ctx, struct nss_cranipc_node_sync *stats)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	/*
	 * Update common node stats
	 */
	spin_lock_bh(&nss_top->stats_lock);
	nss_top->stats_node[NSS_CRANIPC_INTERFACE][NSS_STATS_NODE_RX_PKTS] += stats->node_stats.rx_packets;
	nss_top->stats_node[NSS_CRANIPC_INTERFACE][NSS_STATS_NODE_RX_BYTES] += stats->node_stats.rx_bytes;
	nss_top->stats_node[NSS_CRANIPC_INTERFACE][NSS_STATS_NODE_RX_DROPPED] += stats->node_stats.rx_dropped;
	nss_top->stats_node[NSS_CRANIPC_INTERFACE][NSS_STATS_NODE_TX_PKTS] += stats->node_stats.tx_packets;
	nss_top->stats_node[NSS_CRANIPC_INTERFACE][NSS_STATS_NODE_TX_BYTES] += stats->node_stats.tx_bytes;

	/*
	 * Update cranipc node stats
	 */
	nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_IPC] += stats->dl_ipc;
	nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_RETURNED_IPC] += stats->dl_returned_ipc;

	nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_BUFFERS_IN_USE] = nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_IPC] - nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_RETURNED_IPC];

	if (stats->dl_lowest_latency) {
		nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_LOWEST_LATENCY] = stats->dl_lowest_latency;
	}

	if (stats->dl_highest_latency) {
		nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_HIGHEST_LATENCY] = stats->dl_highest_latency;
	}

	if (stats->dl_270us_pkts) {
		nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_270US_LATENCY] = stats->dl_270us_pkts;
	}

	nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_QUEUE_DROPPED] += stats->dl_queue_dropped;
	nss_top->stats_cranipc[NSS_STATS_CRANIPC_DL_DROPPED_NOT_READY] += stats->dl_dropped_not_ready;

	nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_IPC] += stats->ul_ipc;
	nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_RETURNED_IPC] += stats->ul_returned_ipc;

	nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_BUFFERS_IN_USE] =
			nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_RETURNED_IPC] - nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_IPC];

	if (stats->ul_lowest_latency) {
		nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_LOWEST_LATENCY] = stats->ul_lowest_latency;
	}

	if (stats->ul_highest_latency) {
		nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_HIGHEST_LATENCY] = stats->ul_highest_latency;
	}

	nss_top->stats_cranipc[NSS_STATS_CRANIPC_UL_PAYLOAD_ALLOC_FAILS] += stats->ul_payload_alloc_fails;
	spin_unlock_bh(&nss_top->stats_lock);
}
EXPORT_SYMBOL(nss_cranipc_sync_update);

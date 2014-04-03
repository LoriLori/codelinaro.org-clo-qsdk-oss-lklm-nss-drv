/*
 **************************************************************************
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
 * nss_tx_rx_ipv4.c
 *	NSS IPv4 APIs
 */
#include <linux/ppp_channel.h>
#include "nss_tx_rx_common.h"
#include "nss_ipv4.h"

extern void nss_rx_metadata_ipv4_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_establish *nire);
extern void nss_rx_ipv4_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_conn_sync *nirs);

/*
 * nss_ipv4_driver_update()
 *	Update driver specific information from the messsage.
 */
#if 0
static void nss_ipv4_driver_update(void)
{
	/*
	 * Update statistics maintained by NSS driver
	 */
	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_PKTS] += nirs->flow_rx_packet_count + nirs->return_rx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_BYTES] += nirs->flow_rx_byte_count + nirs->return_rx_byte_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_PKTS] += nirs->flow_tx_packet_count + nirs->return_tx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_BYTES] += nirs->flow_tx_byte_count + nirs->return_tx_byte_count;

	/*
	 * Update the PPPoE interface stats, if there is any PPPoE session on the interfaces.
	 */
	if (nirs->flow_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->flow_pppoe_session_id, (uint8_t *)nirs->flow_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->flow_rx_packet_count, nirs->flow_rx_byte_count,
					nirs->flow_tx_packet_count, nirs->flow_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	if (nirs->return_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->return_pppoe_session_id, (uint8_t *)nirs->return_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->return_rx_packet_count, nirs->return_rx_byte_count,
					nirs->return_tx_packet_count, nirs->return_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	/*
	 * TODO: Update per dev accelerated statistics
	 */
	spin_unlock_bh(&nss_top->stats_lock);
}
#endif

/*
 * nss_ipv4_handler()
 *	Handle NSS -> HLOS messages for IPv4 bridge/route
 */
static void nss_ipv4_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_ipv4_msg *nim = (struct nss_ipv4_msg *)ncm;

/*
 * TODO: Turn back on for new APIs
 */
//	nss_ipv4_msg_callback_t cb;

	BUG_ON(ncm->interface != NSS_IPV4_RX_INTERFACE);

	/*
	 * Sanity check the message type
	 */
	if (ncm->type > NSS_IPV4_MAX_MSG_TYPES) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return;
	}

	if (ncm->len > sizeof(struct nss_ipv4_msg)) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return;
	}


	/*
	 * Update the callback and app_data for NOTIFY messages, IPv4 sends all notify messages
	 * to the same callback/app_data.
	 */
	if (nim->cm.response == NSS_CMM_RESPONSE_NOTIFY) {
		ncm->cb = (uint32_t)nss_ctx->nss_top->ipv4_callback;
		//ncm->app_data = nss_ctx->nss_top->ipv4_app_data;
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Handle deprecated messages.  Eventually these messages should be removed.
	 */
	switch (nim->cm.type) {
	case NSS_IPV4_RX_ESTABLISH_RULE_MSG:
		return nss_rx_metadata_ipv4_rule_establish(nss_ctx, &nim->msg.rule_establish);
		break;

	case NSS_IPV4_RX_CONN_STATS_SYNC_MSG:
		return nss_rx_ipv4_sync(nss_ctx, &nim->msg.conn_stats);
		break;
	}

	/*
	 * Local driver updates for ipv4.
	 */
#if 0
	/*
	 * Do we have a callback?
	 */
	if (!ncm->cb) {
		return;
	}

	/*
	 * Callback
	 */
	cb = (nss_ipv4_msg_callback_t)ncm->cb;
	cb((void *)ncm->app_data, nim);
#endif
}

/*
 * nss_ipv4_tx()
 *	Transmit an ipv4 message to the FW.
 */
nss_tx_status_t nss_ipv4_tx(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_msg *nim2;
	struct nss_cmn_msg *ncm = &nim->cm;
	struct sk_buff *nbuf;
	int32_t status;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: ipv4 msg dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the message
	 */
	if (ncm->interface != NSS_IPV4_RX_INTERFACE) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	if (ncm->type > NSS_IPV4_MAX_MSG_TYPES) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	if (ncm->len > sizeof(struct nss_ipv4_msg)) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: msg dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the message to our skb.
	 */
	nim2 = (struct nss_ipv4_msg *)skb_put(nbuf, sizeof(struct nss_ipv4_msg));
	memcpy(nim2, nim, sizeof(struct nss_ipv4_msg));

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 **********************************
 Register/Unregister/Miscellaneous APIs
 **********************************
 */

/*
 * nss_ipv4_notify_register()
 *	Register to received IPv4 events.
 *
 * NOTE: Do we want to pass an nss_ctx here so that we can register for ipv4 on any core?
 */
struct nss_ctx_instance *nss_ipv4_notify_register(nss_ipv4_msg_callback_t cb, void *app_data)
{
	/*
	 * TODO: We need to have a new array in support of the new API
	 * TODO: If we use a per-context array, we would move the array into nss_ctx based.
	 */
	nss_top_main.ipv4_callback = cb;
	// nss_top_main.ipv4_app_data = app_data;
	return &nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_ipv4_notify_unregister()
 *	Unregister to received IPv4 events.
 *
 * NOTE: Do we want to pass an nss_ctx here so that we can register for ipv4 on any core?
 */
void nss_ipv4_notify_unregister(void)
{
	nss_top_main.ipv4_callback = NULL;
}

/*
 * nss_ipv4_get_mgr()
 *
 * TODO: This only suppports a single ipv4, do we ever want to support more?
 */
struct nss_ctx_instance *nss_ipv4_get_mgr(void)
{
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_ipv4_register_handler()
 *	Register our handler to receive messages for this interface
 */
void nss_ipv4_register_handler()
{
	if (nss_core_register_handler(NSS_IPV4_RX_INTERFACE, nss_ipv4_handler, NULL) != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("IPv4 handler failed to register");
	}
}

EXPORT_SYMBOL(nss_ipv4_tx);
EXPORT_SYMBOL(nss_ipv4_notify_register);
EXPORT_SYMBOL(nss_ipv4_notify_unregister);
EXPORT_SYMBOL(nss_ipv4_get_mgr);
EXPORT_SYMBOL(nss_ipv4_register_handler);

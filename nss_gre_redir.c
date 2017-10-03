/*
 **************************************************************************
 * Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
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

#include "nss_tx_rx_common.h"
#include "nss_gre_redir_stats.h"
#define NSS_GRE_REDIR_TX_TIMEOUT 3000 /* 3 Seconds */

/*
 * Private data structure for handling synchronous messaging.
 */
static struct {
	struct semaphore sem;
	struct completion complete;
	int response;
	void *cb;
	void *app_data;
} nss_gre_redir_pvt;

/*
 * Spinlock to update tunnel stats.
 */
static DEFINE_SPINLOCK(nss_gre_redir_stats_lock);

/*
 * Array to hold tunnel stats along with if_num
 */
static struct nss_gre_redir_tunnel_stats tun_stats[NSS_GRE_REDIR_MAX_INTERFACES];

/*
 * nss_gre_callback()
 *	Callback to handle the completion of HLOS-->NSS messages.
 */
static void nss_gre_redir_callback(void *app_data, struct nss_gre_redir_msg *nim)
{
	nss_gre_redir_msg_callback_t callback = (nss_gre_redir_msg_callback_t)nss_gre_redir_pvt.cb;
	void *data = nss_gre_redir_pvt.app_data;

	nss_gre_redir_pvt.cb = NULL;
	nss_gre_redir_pvt.app_data = NULL;
	nss_gre_redir_pvt.response = NSS_TX_SUCCESS;
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		nss_warning("gre Error response %d\n", nim->cm.response);
		nss_gre_redir_pvt.response = NSS_TX_FAILURE;
	}

	if (callback) {
		callback(data, &nim->cm);
	}

	complete(&nss_gre_redir_pvt.complete);
}

/*
 * nss_gre_redir_tunnel_update_stats()
 *	Update gre_redir tunnel stats.
 */
static void nss_gre_redir_tunnel_update_stats(struct nss_ctx_instance *nss_ctx, int if_num, struct nss_gre_redir_stats_sync_msg *ngss)
{
	int i, j;
	uint32_t type;
	struct net_device *dev;

	type = nss_dynamic_interface_get_type(nss_ctx, if_num);
	dev = nss_cmn_get_interface_dev(nss_ctx, if_num);
	if (!dev) {
		nss_warning("%p: Unable to find net device for the interface %d\n", nss_ctx, if_num);
		return;
	}

	spin_lock_bh(&nss_gre_redir_stats_lock);
	for (i = 0; i < NSS_GRE_REDIR_MAX_INTERFACES; i++) {
		if (tun_stats[i].dev == dev) {
			break;
		}
	}

	if (i == NSS_GRE_REDIR_MAX_INTERFACES) {
		nss_warning("%p: Unable to find tunnel stats instance for interface %d\n", nss_ctx, if_num);
		return;
	}

	nss_assert(tun_stats[i].ref_count);
	switch (type) {
	case NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_HOST_INNER:
	case NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_OFFL_INNER:
	case NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_SJACK_INNER:
		tun_stats[i].node_stats.tx_packets += ngss->node_stats.tx_packets;
		tun_stats[i].node_stats.tx_bytes += ngss->node_stats.tx_bytes;
		tun_stats[i].sjack_tx_packets += ngss->sjack_rx_packets;
		tun_stats[i].tx_dropped += nss_cmn_rx_dropped_sum(&(ngss->node_stats));
		for (j = 0; j < NSS_GRE_REDIR_NUM_RADIO; j++) {
			tun_stats[i].offl_tx_pkts[j] += ngss->offl_rx_pkts[j];
		}

		break;

	case NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_OUTER:
		tun_stats[i].node_stats.rx_packets += ngss->node_stats.rx_packets;
		tun_stats[i].node_stats.rx_bytes += ngss->node_stats.rx_bytes;
		tun_stats[i].sjack_rx_packets += ngss->sjack_rx_packets;
		tun_stats[i].node_stats.rx_dropped[0] += nss_cmn_rx_dropped_sum(&(ngss->node_stats));
		for (j = 0; j < NSS_GRE_REDIR_NUM_RADIO; j++) {
			tun_stats[i].offl_rx_pkts[j] += ngss->offl_rx_pkts[j];
		}

		break;

	default:
		nss_warning("%p: Unknown type for interface %d\n", nss_ctx, if_num);
	}

	spin_unlock_bh(&nss_gre_redir_stats_lock);
}

/*
 * nss_gre_redir_handler()
 *	Handle NSS -> HLOS messages for GRE tunnel.
 */
static void nss_gre_redir_msg_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_gre_redir_msg *ngrm = (struct nss_gre_redir_msg *)ncm;
	void *ctx;
	nss_gre_redir_msg_callback_t cb;

	/*
	 * interface should either be dynamic interface for receiving tunnel msg or GRE_REDIR interface for
	 * receiving base node messages.
	 */
	BUG_ON(((ncm->interface < NSS_DYNAMIC_IF_START) || (ncm->interface >= (NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES))) &&
		ncm->interface != NSS_GRE_REDIR_INTERFACE);

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncm->type >=  NSS_GRE_REDIR_MAX_MSG_TYPES) {
		nss_warning("%p: Received invalid message %d for gre interface", nss_ctx, ncm->type);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_gre_redir_msg)) {
		nss_warning("%p: Length of message is greater than required: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return;
	}

	/*
	 * Update the callback and app_data for NOTIFY messages, gre sends all notify messages
	 * to the same callback/app_data.
	 */
	if (ncm->response == NSS_CMM_RESPONSE_NOTIFY) {
		ncm->cb = (nss_ptr_t)nss_ctx->nss_top->if_rx_msg_callback[ncm->interface];
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	switch (ncm->type) {
	case NSS_GRE_REDIR_RX_STATS_SYNC_MSG:
		/*
		 * Update Tunnel statistics.
		 */
		if (!(nss_is_dynamic_interface(ncm->interface))) {
			nss_warning("%p: Stats received for wrong interface %d\n", nss_ctx, ncm->interface);
			break;
		}

		nss_gre_redir_tunnel_update_stats(nss_ctx, ncm->interface, &ngrm->msg.stats_sync);
		break;
	}

	/*
	 * Do we have a call back
	 */
	if (!ncm->cb) {
		return;
	}

	/*
	 * callback
	 */
	cb = (nss_gre_redir_msg_callback_t)ncm->cb;
	ctx = nss_ctx->subsys_dp_register[ncm->interface].ndev;

	/*
	 * call gre tunnel callback
	 */
	cb(ctx, ncm);
}

/*
 * nss_gre_redir_alloc_and_register_node()
 *	Allocates and registers GRE Inner/Outer type dynamic nodes with NSS.
 */
int nss_gre_redir_alloc_and_register_node(struct net_device *dev,
		nss_gre_redir_data_callback_t data_cb,
		nss_gre_redir_msg_callback_t msg_cb,
		uint32_t type)
{
	int ifnum;
	nss_tx_status_t status;
	struct nss_ctx_instance *nss_ctx;

	if ((type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_HOST_INNER) &&
			(type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_OFFL_INNER) &&
			(type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_SJACK_INNER) &&
			(type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_OUTER)) {

		nss_warning("%p: Unknown type %u\n", dev, type);
		return -1;
	}

	ifnum = nss_dynamic_interface_alloc_node(type);
	if (ifnum == -1) {
		nss_warning("%p: Unable to allocate GRE_REDIR node of type = %u\n", dev, type);
		return -1;
	}

	nss_ctx = nss_gre_redir_register_if(ifnum, dev, data_cb,
			msg_cb, 0, type);
	if (!nss_ctx) {
		nss_warning("Unable to register GRE_REDIR node of type = %u\n", type);
		status = nss_dynamic_interface_dealloc_node(ifnum, type);
		if (status != NSS_TX_SUCCESS) {
			nss_warning("%p: Unable to deallocate node.\n", nss_ctx);
		}

		return -1;
	}

	return ifnum;
}
EXPORT_SYMBOL(nss_gre_redir_alloc_and_register_node);

/*
 * nss_gre_redir_configure_inner_node()
 *	Configure an inner type gre_redir dynamic node.
 */
nss_tx_status_t nss_gre_redir_configure_inner_node(int ifnum,
		struct nss_gre_redir_inner_configure_msg *ngrcm,
		void *msg_completion_cb)
{
	struct nss_gre_redir_msg config;
	uint32_t len, iftype, outerif_type;
	nss_tx_status_t status;

	struct nss_ctx_instance *nss_ctx = nss_gre_redir_get_context();
	if (!nss_ctx) {
		nss_warning("Unable to retrieve NSS context.\n");
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	if (ngrcm->ip_hdr_type != NSS_GRE_REDIR_IP_HDR_TYPE_IPV4 &&
			ngrcm->ip_hdr_type != NSS_GRE_REDIR_IP_HDR_TYPE_IPV6) {
		nss_warning("%p: Unknown IP header type %u\n", nss_ctx, ngrcm->ip_hdr_type);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	if (ngrcm->gre_version != NSS_GRE_REDIR_HEADER_VERSION) {
		nss_warning("%p: Incorrect header version %u\n", nss_ctx, ngrcm->gre_version);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	iftype = nss_dynamic_interface_get_type(nss_ctx, ifnum);
	if (!((iftype == NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_HOST_INNER) ||
			(iftype == NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_OFFL_INNER) ||
			(iftype == NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_SJACK_INNER))) {

		nss_warning("%p: Incorrect interface type %u\n", nss_ctx, iftype);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	outerif_type = nss_dynamic_interface_get_type(nss_ctx, ngrcm->except_outerif);
	if (outerif_type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_OUTER) {
		nss_warning("%p: Incorrect type for exception interface %u\n", nss_ctx, outerif_type);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	len = sizeof(struct nss_gre_redir_inner_configure_msg);

	/*
	 * Configure the node
	 */
	nss_cmn_msg_init(&config.cm, ifnum, NSS_GRE_REDIR_TX_TUNNEL_INNER_CONFIGURE_MSG, len, msg_completion_cb, NULL);
	config.msg.inner_configure.ip_hdr_type = ngrcm->ip_hdr_type;
	config.msg.inner_configure.ip_df_policy = ngrcm->ip_df_policy;
	config.msg.inner_configure.gre_version = ngrcm->gre_version;
	config.msg.inner_configure.ip_ttl = ngrcm->ip_ttl;
	config.msg.inner_configure.except_outerif = ngrcm->except_outerif;
	memcpy((void *)config.msg.inner_configure.ip_src_addr, (void *)(ngrcm->ip_src_addr), sizeof(ngrcm->ip_src_addr));
	memcpy((void *)config.msg.inner_configure.ip_dest_addr, (void *)(ngrcm->ip_dest_addr), sizeof(ngrcm->ip_dest_addr));

	status = nss_gre_redir_tx_msg_sync(nss_ctx, &config);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("%p: Unable to configure inner node %d.\n", nss_ctx, ifnum);
	}

	return status;
}
EXPORT_SYMBOL(nss_gre_redir_configure_inner_node);

/*
 * nss_gre_redir_configure_outer_node()
 *	Configure an outer type gre_redir dynamic node.
 */
nss_tx_status_t nss_gre_redir_configure_outer_node(int ifnum,
		struct nss_gre_redir_outer_configure_msg *ngrcm,
		void *msg_completion_cb)
{
	struct nss_gre_redir_msg config;
	struct nss_ctx_instance *nss_ctx;
	nss_tx_status_t status;
	uint32_t hostif_type, offlif_type, sjackif_type, iftype;
	uint32_t len = sizeof(struct nss_gre_redir_outer_configure_msg);

	nss_ctx = nss_gre_redir_get_context();
	if (!nss_ctx) {
		nss_warning("Unable to retrieve NSS context.\n");
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	if (ngrcm->ip_hdr_type != NSS_GRE_REDIR_IP_HDR_TYPE_IPV4 &&
			ngrcm->ip_hdr_type != NSS_GRE_REDIR_IP_HDR_TYPE_IPV6) {
		nss_warning("%p: Unknown IP header type %u\n", nss_ctx, ngrcm->ip_hdr_type);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	iftype = nss_dynamic_interface_get_type(nss_ctx, ifnum);
	if (iftype != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_OUTER) {
		nss_warning("%p: Incorrect interface type %u\n", nss_ctx, iftype);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	hostif_type = nss_dynamic_interface_get_type(nss_ctx, ngrcm->except_hostif);
	offlif_type = nss_dynamic_interface_get_type(nss_ctx, ngrcm->except_offlif);
	sjackif_type = nss_dynamic_interface_get_type(nss_ctx, ngrcm->except_sjackif);
	if ((hostif_type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_HOST_INNER) ||
			(offlif_type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_OFFL_INNER) ||
			(ngrcm->except_sjackif
			 && sjackif_type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_SJACK_INNER)) {

		nss_warning("%p: Incorrect type for exception interface hostif_type = %u"
				"offlif_type = %u sjackif_type = %u\n", nss_ctx, hostif_type,
				offlif_type, sjackif_type);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	/*
	 * Configure the node
	 */
	nss_cmn_msg_init(&config.cm, ifnum, NSS_GRE_REDIR_TX_TUNNEL_OUTER_CONFIGURE_MSG, len, msg_completion_cb, NULL);
	config.msg.outer_configure.ip_hdr_type = ngrcm->ip_hdr_type;
	config.msg.outer_configure.rps_hint = ngrcm->rps_hint;
	config.msg.outer_configure.except_hostif = ngrcm->except_hostif;
	config.msg.outer_configure.except_offlif = ngrcm->except_offlif;
	config.msg.outer_configure.except_sjackif = ngrcm->except_sjackif;

	status = nss_gre_redir_tx_msg_sync(nss_ctx, &config);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("%p: Unable to configure outer node %d\n", nss_ctx, ifnum);
	}

	return status;
}
EXPORT_SYMBOL(nss_gre_redir_configure_outer_node);

/*
 * nss_gre_redir_get_stats()
 *	Get gre_redir tunnel stats.
 */
bool nss_gre_redir_get_stats(int index, struct nss_gre_redir_tunnel_stats *stats)
{
	spin_lock_bh(&nss_gre_redir_stats_lock);
	if (tun_stats[index].ref_count == 0) {
		spin_unlock_bh(&nss_gre_redir_stats_lock);
		return false;
	}

	memcpy(stats, &tun_stats[index], sizeof(struct nss_gre_redir_tunnel_stats));
	spin_unlock_bh(&nss_gre_redir_stats_lock);
	return true;
}
EXPORT_SYMBOL(nss_gre_redir_get_stats);

/*
 * nss_gre_redir_tx_msg()
 *	Transmit a GRE message to NSS FW.
 */
nss_tx_status_t nss_gre_redir_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_gre_redir_msg *msg)
{
	struct nss_gre_redir_msg *nm;
	struct nss_cmn_msg *ncm = &msg->cm;
	struct sk_buff *nbuf;
	int32_t status;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: GRE msg dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the message
	 */

	/*
	 * interface should either be dynamic interface to transmit tunnel msg or GRE_REDIR interface to transmit
	 * base node messages.
	 */
	if (((ncm->interface < NSS_DYNAMIC_IF_START) || (ncm->interface >= (NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES))) &&
		ncm->interface != NSS_GRE_REDIR_INTERFACE) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	if (ncm->type > NSS_GRE_REDIR_MAX_MSG_TYPES) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_gre_redir_msg)) {
		nss_warning("%p: message length is invalid: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return NSS_TX_FAILURE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]);
		nss_warning("%p: msg dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the message to our skb
	 */
	nm = (struct nss_gre_redir_msg *)skb_put(nbuf, sizeof(struct nss_gre_redir_msg));
	memcpy(nm, msg, sizeof(struct nss_gre_redir_msg));

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'gre message' \n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx, NSS_H2N_INTR_DATA_COMMAND_QUEUE);
	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}
EXPORT_SYMBOL(nss_gre_redir_tx_msg);

/*
 * nss_gre_redir_tx_msg_sync()
 *	Transmit a GRE redir message to NSS firmware synchronously.
 */
nss_tx_status_t nss_gre_redir_tx_msg_sync(struct nss_ctx_instance *nss_ctx, struct nss_gre_redir_msg *ngrm)
{
	nss_tx_status_t status;
	int ret = 0;

	down(&nss_gre_redir_pvt.sem);
	nss_gre_redir_pvt.cb = (void *)ngrm->cm.cb;
	nss_gre_redir_pvt.app_data = (void *)ngrm->cm.app_data;
	ngrm->cm.cb = (nss_ptr_t)nss_gre_redir_callback;
	ngrm->cm.app_data = (nss_ptr_t)NULL;
	status = nss_gre_redir_tx_msg(nss_ctx, ngrm);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("%p: gre_tx_msg failed\n", nss_ctx);
		up(&nss_gre_redir_pvt.sem);
		return status;
	}

	ret = wait_for_completion_timeout(&nss_gre_redir_pvt.complete, msecs_to_jiffies(NSS_GRE_REDIR_TX_TIMEOUT));
	if (!ret) {
		nss_warning("%p: GRE tx sync failed due to timeout\n", nss_ctx);
		nss_gre_redir_pvt.response = NSS_TX_FAILURE;
	}

	status = nss_gre_redir_pvt.response;
	up(&nss_gre_redir_pvt.sem);
	return status;
}
EXPORT_SYMBOL(nss_gre_redir_tx_msg_sync);

/*
 * nss_gre_redir_tx_buf()
 *	Send packet to gre_redir interface owned by NSS.
 */
nss_tx_status_t nss_gre_redir_tx_buf(struct nss_ctx_instance *nss_ctx, struct sk_buff *os_buf, uint32_t if_num)
{
	int32_t status;
	uint32_t type;

	nss_trace("%p: gre_redir If Tx packet, id:%d, data=%p", nss_ctx, if_num, os_buf->data);
	NSS_VERIFY_CTX_MAGIC(nss_ctx);

	/*
	 * We expect Tx packets to the tunnel only from an interface of
	 * type GRE_REDIR_WIFI_HOST_INNER.
	 */
	type = nss_dynamic_interface_get_type(nss_ctx, if_num);
	if (type != NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR_WIFI_HOST_INNER) {
		nss_warning("%p: Unknown type for interface %u\n", nss_ctx, type);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Tx' packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_buffer(nss_ctx, if_num, os_buf, NSS_IF_DATA_QUEUE_0, H2N_BUFFER_PACKET, 0);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Unable to enqueue 'Phys If Tx' packet\n", nss_ctx);
		if (status == NSS_CORE_STATUS_FAILURE_QUEUE) {
			return NSS_TX_FAILURE_QUEUE;
		}

		return NSS_TX_FAILURE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx, NSS_H2N_INTR_DATA_COMMAND_QUEUE);
	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_PACKET]);
	return NSS_TX_SUCCESS;
}
EXPORT_SYMBOL(nss_gre_redir_tx_buf);

/*
 ***********************************
 * Register/Unregister/Miscellaneous APIs
 ***********************************
 */

/*
 * nss_gre_redir_register_if()
 *	Register dynamic node for GRE redir.
 */
struct nss_ctx_instance *nss_gre_redir_register_if(uint32_t if_num, struct net_device *netdev, nss_gre_redir_data_callback_t cb_func_data,
							nss_gre_redir_msg_callback_t cb_func_msg, uint32_t features, uint32_t type)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.gre_redir_handler_id];
	uint32_t status;
	int i, idx = -1;

	nss_assert(nss_ctx);
	nss_assert((if_num >= NSS_DYNAMIC_IF_START) && (if_num < (NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES)));

	spin_lock_bh(&nss_gre_redir_stats_lock);
	for (i = 0; i < NSS_GRE_REDIR_MAX_INTERFACES; i++) {
		if (tun_stats[i].dev == netdev) {
			idx = i;
			break;
		}

		if ((idx == -1) && (tun_stats[i].ref_count == 0)) {
			idx = i;
		}
	}

	if (idx == -1) {
		spin_unlock_bh(&nss_gre_redir_stats_lock);
		nss_warning("%p: Maximum number of gre_redir tunnel_stats instances are already allocated\n", nss_ctx);
		return NULL;
	}

	if (!tun_stats[idx].ref_count) {
		tun_stats[idx].dev = netdev;
	}
	tun_stats[idx].ref_count++;

	spin_unlock_bh(&nss_gre_redir_stats_lock);

	/*
	 * Registering handler for sending tunnel interface msgs to NSS.
	 */
	status = nss_core_register_handler(nss_ctx, if_num, nss_gre_redir_msg_handler, NULL);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		spin_lock_bh(&nss_gre_redir_stats_lock);
		tun_stats[idx].ref_count--;
		if (!tun_stats[idx].ref_count) {
			tun_stats[idx].dev = NULL;
		}
		spin_unlock_bh(&nss_gre_redir_stats_lock);

		nss_warning("%p: Not able to register handler for gre_redir interface %d with NSS core\n", nss_ctx, if_num);
		return NULL;
	}

	nss_core_register_subsys_dp(nss_ctx, if_num, cb_func_data, NULL, NULL, netdev, features);
	nss_core_set_subsys_dp_type(nss_ctx, netdev, if_num, type);
	nss_top_main.if_rx_msg_callback[if_num] = cb_func_msg;
	return nss_ctx;
}
EXPORT_SYMBOL(nss_gre_redir_register_if);

/*
 * nss_gre_redir_unregister_if()
 *	Unregister dynamic node for GRE redir.
 */
bool nss_gre_redir_unregister_if(uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.gre_redir_handler_id];
	uint32_t status;
	struct net_device *dev;
	int i;

	nss_assert(nss_ctx);
	nss_assert((if_num >= NSS_DYNAMIC_IF_START) && (if_num < (NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES)));

	dev = nss_cmn_get_interface_dev(nss_ctx, if_num);
	if (!dev) {
		nss_warning("%p: Unable to find net device for the interface %d\n", nss_ctx, if_num);
		return false;
	}

	status = nss_core_unregister_handler(nss_ctx, if_num);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("%p: Not able to unregister handler for gre_redir interface %d with NSS core\n", nss_ctx, if_num);
		return false;
	}

	nss_core_set_subsys_dp_type(nss_ctx, dev, if_num, NSS_DYNAMIC_INTERFACE_TYPE_NONE);
	nss_core_unregister_subsys_dp(nss_ctx, if_num);
	nss_top_main.if_rx_msg_callback[if_num] = NULL;
	spin_lock_bh(&nss_gre_redir_stats_lock);

	/*
	 * Update/Clear the tunnel stats entry for this tunnel.
	 */
	for (i = 0; i < NSS_GRE_REDIR_MAX_INTERFACES; i++) {
		if (tun_stats[i].dev == dev) {
			tun_stats[i].ref_count--;
			if (!tun_stats[i].ref_count) {
				tun_stats[i].dev = NULL;
			}

			break;
		}
	}

	spin_unlock_bh(&nss_gre_redir_stats_lock);
	return true;
}
EXPORT_SYMBOL(nss_gre_redir_unregister_if);

/*
 * nss_get_gre_redir_context()
 *	Retrieve context for GRE redir.
 */
struct nss_ctx_instance *nss_gre_redir_get_context(void)
{
	return (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.gre_redir_handler_id];
}
EXPORT_SYMBOL(nss_gre_redir_get_context);

/*
 * nss_gre_redir_register_handler()
 *	Registering handler for sending msg to base gre_redir node on NSS.
 */
void nss_gre_redir_register_handler(void)
{
	struct nss_ctx_instance *nss_ctx = nss_gre_redir_get_context();
	uint32_t status;

	sema_init(&nss_gre_redir_pvt.sem, 1);
	init_completion(&nss_gre_redir_pvt.complete);
	memset(tun_stats, 0, sizeof(struct nss_gre_redir_tunnel_stats)*NSS_GRE_REDIR_MAX_INTERFACES);
	status = nss_core_register_handler(nss_ctx, NSS_GRE_REDIR_INTERFACE, nss_gre_redir_msg_handler, NULL);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("%p: Not able to register handler for gre_redir base interface with NSS core\n", nss_ctx);
		return;
	}

	nss_gre_redir_stats_dentry_create();
}

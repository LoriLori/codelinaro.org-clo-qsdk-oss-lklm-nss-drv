/*
 **************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE
 **************************************************************************
 */

#include "nss_tx_rx_common.h"
#include "nss_tls_log.h"

#define NSS_TLS_INTERFACE_MAX_LONG BITS_TO_LONGS(NSS_MAX_NET_INTERFACES)
#define NSS_TLS_STATS_MAX_LINES (NSS_STATS_NODE_MAX + 32)
#define NSS_TLS_STATS_SIZE_PER_IF (NSS_STATS_MAX_STR_LENGTH * NSS_TLS_STATS_MAX_LINES)
#define NSS_TLS_TX_TIMEOUT 3000 /* 3 Seconds */

/*
 * Private data structure for handling synchronous messaging.
 */
static struct nss_tls_pvt {
	struct semaphore sem;
	struct completion complete;
	struct nss_tls_msg ntcm;
	unsigned long if_map[NSS_TLS_INTERFACE_MAX_LONG];
} tls_pvt;

/*
 * nss_tls_stats_sync()
 *	Update tls node statistics.
 */
static void nss_tls_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm)
{
	struct nss_tls_msg *ndcm = (struct nss_tls_msg *)ncm;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_tls_ctx_stats *msg_stats = &ndcm->msg.stats;
	uint64_t *if_stats;
	int i;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * Update common node stats,
	 * Note: TLS only supports a single queue for RX
	 */
	if_stats = nss_top->stats_node[ncm->interface];
	if_stats[NSS_STATS_NODE_RX_PKTS] += msg_stats->pkt.rx_packets;
	if_stats[NSS_STATS_NODE_RX_BYTES] += msg_stats->pkt.rx_bytes;

	for (i = 0; i < NSS_MAX_NUM_PRI; i++)
		if_stats[NSS_STATS_NODE_RX_QUEUE_0_DROPPED + i] += msg_stats->pkt.rx_dropped[i];

	if_stats[NSS_STATS_NODE_TX_PKTS] += msg_stats->pkt.tx_packets;
	if_stats[NSS_STATS_NODE_TX_BYTES] += msg_stats->pkt.tx_bytes;

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_tls_stats_read()
 *	Read tls node statiistics.
 */
static ssize_t nss_tls_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_ctx_instance *nss_ctx = nss_tls_get_context();
	enum nss_dynamic_interface_type type;
	ssize_t bytes_read = 0;
	size_t len = 0, size;
	uint32_t if_num;
	char *buf;

	size = NSS_TLS_STATS_SIZE_PER_IF * bitmap_weight(tls_pvt.if_map, NSS_MAX_NET_INTERFACES);

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Common node stats for each TLS dynamic interface.
	 */
	for_each_set_bit(if_num, tls_pvt.if_map, NSS_MAX_NET_INTERFACES) {
		type = nss_dynamic_interface_get_type(nss_ctx, if_num);

		switch (type) {
		case NSS_DYNAMIC_INTERFACE_TYPE_TLS_INNER:
			len += scnprintf(buf + len, size - len, "\nInner if_num:%03u", if_num);
			break;

		case NSS_DYNAMIC_INTERFACE_TYPE_TLS_OUTER:
			len += scnprintf(buf + len, size - len, "\nOuter if_num:%03u", if_num);
			break;

		default:
			len += scnprintf(buf + len, size - len, "\nUnknown(%d) if_num:%03u", type, if_num);
			break;
		}

		len += scnprintf(buf + len, size - len, "\n-------------------\n");
		len = nss_stats_fill_common_stats(if_num, NSS_STATS_SINGLE_INSTANCE, buf, len, size - len, "tls");
	}

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, buf, len);
	kfree(buf);

	return bytes_read;
}

/*
 * nss_tls_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(tls)

/*
 * nss_tls_verify_ifnum()
 *	Verify if the interface number is a TLS interface.
 */
static bool nss_tls_verify_ifnum(struct nss_ctx_instance *nss_ctx, uint32_t if_num)
{
	enum nss_dynamic_interface_type type = nss_dynamic_interface_get_type(nss_ctx, if_num);

	if (type == NSS_DYNAMIC_INTERFACE_TYPE_TLS_INNER)
		return true;

	if (type == NSS_DYNAMIC_INTERFACE_TYPE_TLS_OUTER)
		return true;

	if (if_num == NSS_TLS_INTERFACE)
		return true;

	return false;
}

/*
 * nss_tls_handler()
 *	Handle NSS -> HLOS messages for tls tunnel
 */
static void nss_tls_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, void *data)
{
	nss_tls_msg_callback_t cb;
	void *app_data;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);

	nss_trace("%p: handle event for interface num :%u", nss_ctx, ncm->interface);

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncm->type >= NSS_TLS_MSG_MAX) {
		nss_warning("%p:Bad message type(%d) for TLS interface %d", nss_ctx, ncm->type, ncm->interface);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_tls_msg)) {
		nss_warning("%p:Bad message length(%d)", nss_ctx, ncm->len);
		return;
	}

	if (ncm->type == NSS_TLS_MSG_TYPE_CTX_SYNC)
		nss_tls_stats_sync(nss_ctx, ncm);

	/*
	 * Update the callback and app_data for NOTIFY messages
	 */
	if (ncm->response == NSS_CMN_RESPONSE_NOTIFY) {
		ncm->cb = (nss_ptr_t)nss_top_main.if_rx_msg_callback[ncm->interface];
		ncm->app_data = (nss_ptr_t)nss_ctx->nss_rx_interface_handlers[nss_ctx->id][ncm->interface].app_data;
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Trace messages.
	 */
	nss_tls_log_rx_msg((struct nss_tls_msg *)ncm);

	/*
	 * Callback
	 */
	cb = (nss_tls_msg_callback_t)ncm->cb;
	app_data = (void *)ncm->app_data;

	/*
	 * Call TLS session callback
	 */
	if (!cb) {
		nss_warning("%p: No callback for tls session interface %d", nss_ctx, ncm->interface);
		return;
	}

	nss_trace("%p: calling tlsmgr event handler(%u)", nss_ctx, ncm->interface);
	cb(app_data, ncm);
}

/*
 * nss_tls_sync_resp()
 *	Callback to handle the completion of HLOS-->NSS messages.
 */
static void nss_tls_sync_resp(void *app_data, struct nss_cmn_msg *ncm)
{
	struct nss_tls_msg *pvt_msg = app_data;
	struct nss_tls_msg *resp_msg = container_of(ncm, struct nss_tls_msg, cm);

	/*
	 * Copy response message to pvt message
	 */
	memcpy(pvt_msg, resp_msg, sizeof(*resp_msg));

	/*
	 * Write memory barrier
	 */
	smp_wmb();

	complete(&tls_pvt.complete);
}

/*
 * nss_tls_tx_buf()
 *	Transmit buffer over TLS interface
 */
nss_tx_status_t nss_tls_tx_buf(struct sk_buff *skb, uint32_t if_num, struct nss_ctx_instance *nss_ctx)
{
	int32_t status;

	if (!nss_tls_verify_ifnum(nss_ctx, if_num))
		return NSS_TX_FAILURE;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: tx_data packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_buffer(nss_ctx, if_num, skb, NSS_IF_H2N_DATA_QUEUE, H2N_BUFFER_PACKET, 0);
	switch (status) {
	case NSS_CORE_STATUS_SUCCESS:
		break;

	case NSS_CORE_STATUS_FAILURE_QUEUE: /* queue full condition */
		nss_warning("%p: H2N queue full for tx_buf", nss_ctx);
		return NSS_TX_FAILURE_QUEUE;

	default:
		nss_warning("%p: general failure for tx_buf", nss_ctx);
		return NSS_TX_FAILURE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx, NSS_H2N_INTR_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}
EXPORT_SYMBOL(nss_tls_tx_buf);

/*
 * nss_tls_tx_msg()
 *	Transmit a TLS message to NSS firmware
 */
nss_tx_status_t nss_tls_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_tls_msg *msg)
{
	struct nss_cmn_msg *ncm = &msg->cm;

	if (ncm->type >= NSS_TLS_MSG_MAX) {
		nss_warning("%p: tls message type out of range: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	if (!nss_tls_verify_ifnum(nss_ctx, ncm->interface)) {
		nss_warning("%p: tls message interface is bad: %u", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	/*
	 * Trace messages.
	 */
	nss_tls_log_tx_msg(msg);

	return nss_core_send_cmd(nss_ctx, msg, sizeof(*msg), NSS_NBUF_PAYLOAD_SIZE);
}
EXPORT_SYMBOL(nss_tls_tx_msg);

/*
 * nss_tls_tx_msg_sync()
 *	Transmit a TLS message to NSS firmware synchronously.
 */
nss_tx_status_t nss_tls_tx_msg_sync(struct nss_ctx_instance *nss_ctx, uint32_t if_num,
					enum nss_tls_msg_type type, uint16_t len,
					struct nss_tls_msg *ntcm)
{
	struct nss_tls_msg *local_ntcm = &tls_pvt.ntcm;
	nss_tx_status_t status;
	int ret = 0;

	/*
	 * Length of the message should be the based on type
	 */
	if (len > sizeof(struct nss_tls_msg)) {
		nss_warning("%p: Invalid message length(%u), type (%d), I/F(%u)\n", nss_ctx, len, type, if_num);
		return NSS_TX_FAILURE;
	}

	down(&tls_pvt.sem);

	/*
	 * We need to copy the message content into the actual message
	 * to be sent to NSS
	 */
	memset(local_ntcm, 0, sizeof(*local_ntcm));

	nss_tls_msg_init(local_ntcm, if_num, type, len, nss_tls_sync_resp, local_ntcm);
	memcpy(&local_ntcm->msg, &ntcm->msg, len);

	status = nss_tls_tx_msg(nss_ctx, local_ntcm);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("%p: Failed to send message\n", nss_ctx);
		goto done;
	}

	ret = wait_for_completion_timeout(&tls_pvt.complete, msecs_to_jiffies(NSS_TLS_TX_TIMEOUT));
	if (!ret) {
		nss_warning("%p: Failed to receive response, timeout(%d)\n", nss_ctx, ret);
		status = NSS_TX_FAILURE_NOT_READY;
		goto done;
	}

	/*
	 * Read memory barrier
	 */
	smp_rmb();

	if (local_ntcm->cm.response != NSS_CMN_RESPONSE_ACK) {
		status = NSS_TX_FAILURE;
		ntcm->cm.response = local_ntcm->cm.response;
		ntcm->cm.error = local_ntcm->cm.error;
		goto done;
	}

	/*
	 * Copy the message received
	 */
	memcpy(&ntcm->msg, &local_ntcm->msg, len);

done:
	up(&tls_pvt.sem);
	return status;
}
EXPORT_SYMBOL(nss_tls_tx_msg_sync);


/*
 * nss_tls_notify_register()
 *	Register a handler for notification from NSS firmware.
 */
struct nss_ctx_instance *nss_tls_notify_register(uint32_t if_num, nss_tls_msg_callback_t ev_cb, void *app_data)
{
	struct nss_ctx_instance *nss_ctx = nss_tls_get_context();
	uint32_t ret;

	BUG_ON(!nss_ctx);

	ret = nss_core_register_handler(nss_ctx, if_num, nss_tls_handler, app_data);
	if (ret != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("%p: unable to register event handler for interface(%u)", nss_ctx, if_num);
		return NULL;
	}

	nss_top_main.if_rx_msg_callback[if_num] = ev_cb;

	return nss_ctx;
}
EXPORT_SYMBOL(nss_tls_notify_register);

/*
 * nss_tls_notify_unregister()
 *	Unregister notification callback handler.
 */
void nss_tls_notify_unregister(uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = nss_tls_get_context();
	uint32_t ret;

	BUG_ON(!nss_ctx);

	ret = nss_core_unregister_handler(nss_ctx, if_num);
	if (ret != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("%p: unable to un register event handler for interface(%u)", nss_ctx, if_num);
		return;
	}

	nss_top_main.if_rx_msg_callback[if_num] = NULL;

	return;
}
EXPORT_SYMBOL(nss_tls_notify_unregister);

/*
 * nss_tls_register_if()
 *	Register data and event callback handlers for dynamic interface.
 */
struct nss_ctx_instance *nss_tls_register_if(uint32_t if_num,
						  nss_tls_data_callback_t data_cb,
						  nss_tls_msg_callback_t ev_cb,
						  struct net_device *netdev,
						  uint32_t features,
						  uint32_t type,
						  void *app_data)
{
	struct nss_ctx_instance *nss_ctx = nss_tls_get_context();
	uint32_t ret;

	if (!nss_tls_verify_ifnum(nss_ctx, if_num)) {
		nss_warning("%p: TLS Interface is not dynamic:%u", nss_ctx, if_num);
		return NULL;
	}

	if (nss_ctx->subsys_dp_register[if_num].ndev) {
		nss_warning("%p: Cannot find free slot for TLS NSS I/F:%u", nss_ctx, if_num);
		return NULL;
	}

	nss_core_register_subsys_dp(nss_ctx, if_num, data_cb, NULL, app_data, netdev, features);
	nss_core_set_subsys_dp_type(nss_ctx, netdev, if_num, type);

	ret = nss_core_register_handler(nss_ctx, if_num, nss_tls_handler, app_data);
	if (ret != NSS_CORE_STATUS_SUCCESS) {
		nss_warning("%p: unable to register event handler for interface(%u)", nss_ctx, if_num);
		return NULL;
	}

	nss_top_main.if_rx_msg_callback[if_num] = ev_cb;

	/*
	 * Atomically set the bitmap for the interface number
	 */
	set_bit(if_num, tls_pvt.if_map);
	return nss_ctx;
}
EXPORT_SYMBOL(nss_tls_register_if);

/*
 * nss_tls_unregister_if()
 *	Unregister data and event callback handlers for the interface.
 */
void nss_tls_unregister_if(uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = nss_tls_get_context();

	if (!nss_ctx->subsys_dp_register[if_num].ndev) {
		nss_warning("%p: Cannot find registered netdev for TLS NSS I/F:%u", nss_ctx, if_num);
		return;
	}

	/*
	 * Atomically clear the bitmap for the interface number
	 */
	clear_bit(if_num, tls_pvt.if_map);

	nss_core_unregister_handler(nss_ctx, if_num);
	nss_top_main.if_rx_msg_callback[if_num] = NULL;

	nss_core_unregister_subsys_dp(nss_ctx, if_num);
}
EXPORT_SYMBOL(nss_tls_unregister_if);

/*
 * nss_tls_get_context()
 *	Return TLS NSS context.
 */
struct nss_ctx_instance *nss_tls_get_context(void)
{
	return (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.tls_handler_id];
}
EXPORT_SYMBOL(nss_tls_get_context);

/*
 * nss_tls_get_device()
 *	Gets the original device from probe.
 */
struct device *nss_tls_get_dev(struct nss_ctx_instance *nss_ctx)
{
	return nss_ctx->dev;
}
EXPORT_SYMBOL(nss_tls_get_dev);

/*
 * nss_tls_msg_init()
 *	Initialize nss_tls msg to be sent asynchronously.
 */
void nss_tls_msg_init(struct nss_tls_msg *ncm, uint32_t if_num, uint32_t type, uint32_t len, void *cb, void *app_data)
{
	nss_cmn_msg_init(&ncm->cm, if_num, type, len, cb, app_data);
}
EXPORT_SYMBOL(nss_tls_msg_init);

/*
 * nss_tls_msg_sync_init()
 *	Initialize nss_tls_msg to be sent synchronously.
 */
void nss_tls_msg_sync_init(struct nss_tls_msg *ncm, uint32_t if_num, uint32_t type, uint32_t len)
{
	nss_cmn_msg_sync_init(&ncm->cm, if_num, type, len);
}
EXPORT_SYMBOL(nss_tls_msg_sync_init);

/*
 * nss_tls_register_handler()
 *	TLS initialization.
 */
void nss_tls_register_handler(void)
{
	sema_init(&tls_pvt.sem, 1);
	init_completion(&tls_pvt.complete);
	nss_stats_create_dentry("tls", &nss_tls_stats_ops);
}

/*
 **************************************************************************
 * Copyright (c) 2013-2018, The Linux Foundation. All rights reserved.
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
 * nss_pppoe.c
 *	NSS PPPoE APIs
 */

#include "nss_tx_rx_common.h"
#include <linux/if_pppox.h>
#include "nss_pppoe_stats.h"

/*
 * nss_pppoe_tx()
 *	Transmit an PPPoe message to the FW.
 */
nss_tx_status_t nss_pppoe_tx(struct nss_ctx_instance *nss_ctx, struct nss_pppoe_msg *nim)
{
	struct nss_cmn_msg *ncm = &nim->cm;

	/*
	 * Sanity check the message
	 */
	if (ncm->interface != NSS_PPPOE_RX_INTERFACE) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	if (ncm->type > NSS_PPPOE_MAX) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	return nss_core_send_cmd(nss_ctx, nim, sizeof(*nim), NSS_NBUF_PAYLOAD_SIZE);
}

/*
 **********************************
 Rx APIs
 **********************************
 */

/*
 * nss_pppoe_rx_msg_handler()
 *	Handle NSS -> HLOS messages for PPPoE
 */
static void nss_pppoe_rx_msg_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_pppoe_msg *nim = (struct nss_pppoe_msg *)ncm;

	BUG_ON(ncm->interface != NSS_PPPOE_RX_INTERFACE);

	/*
	 * Sanity check the message type
	 */
	if (ncm->type > NSS_PPPOE_MAX) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_pppoe_msg)) {
		nss_warning("%p: message length is invalid: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return;
	}

	/*
	 * Log failures
	 */
	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Handling PPPoE messages coming from NSS fw.
	 */
	switch (nim->cm.type) {
	case NSS_PPPOE_RX_NODE_STATS_SYNC:
		nss_pppoe_stats_node_sync(nss_ctx, &nim->msg.pppoe_node_stats_sync);
		break;
	case NSS_PPPOE_RX_CONN_STATS_SYNC:
		nss_pppoe_stats_exception_sync(nss_ctx, &nim->msg.pppoe_conn_stats_sync);
		break;
	case NSS_PPPOE_RX_SESSION_RESET:
		nss_pppoe_stats_session_reset(nss_ctx, &nim->msg.pppoe_session_reset);
		break;
	default:
		nss_warning("%p: Received response %d for type %d, interface %d",
				nss_ctx, ncm->response, ncm->type, ncm->interface);
	}
}

/*
 * nss_pppoe_register_handler()
 */
void nss_pppoe_register_handler(struct nss_ctx_instance *nss_ctx)
{
	nss_core_register_handler(nss_ctx, NSS_PPPOE_RX_INTERFACE, nss_pppoe_rx_msg_handler, NULL);

	nss_pppoe_stats_dentry_create();
}

/*
 * nss_pppoe_msg_init()
 *	Initialize pppoe message.
 */
void nss_pppoe_msg_init(struct nss_pppoe_msg *npm, uint16_t if_num, uint32_t type, uint32_t len,
			void *cb, void *app_data)
{
	nss_cmn_msg_init(&npm->cm, if_num, type, len, (void *)cb, app_data);
}

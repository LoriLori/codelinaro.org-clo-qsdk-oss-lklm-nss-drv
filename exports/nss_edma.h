/*
 **************************************************************************
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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
 * @file nss_edma.h
 *	NSS EDMA interface definitions.
 */

#ifndef __NSS_EDMA_H
#define __NSS_EDMA_H

/**
 * @addtogroup nss_edma_subsystem
 * @{
 */

/*
 * NSS EDMA port and ring defines
 */
#define NSS_EDMA_NUM_PORTS_MAX		256
		/**< Maximum number of EDMA ports. */
#define NSS_EDMA_NUM_RX_RING_MAX	16
		/**< Maximum number of physical EDMA Rx rings. */
#define NSS_EDMA_NUM_RXFILL_RING_MAX	8
		/**< Maximum number of physical EDMA Rx fill rings. */
#define NSS_EDMA_NUM_TX_RING_MAX	24
		/**< Maximum number of physical EDMA Tx rings. */
#define NSS_EDMA_NUM_TXCMPL_RING_MAX	8
		/**< Maximum number of physical EDMA Tx complete rings. */
#define NSS_EDMA_STATS_MSG_MAX_PORTS	16
		/**< Maximum ports processed per statistics message. */

/**
 * nss_edma_metadata_types
 *	Message types for EDMA requests and responses.
 */
enum nss_edma_metadata_types {
	NSS_METADATA_TYPE_EDMA_PORT_STATS_SYNC,
	NSS_METADATA_TYPE_EDMA_RING_STATS_SYNC,
	NSS_METADATA_TYPE_EDMA_MAX
};

/**
 * nss_edma_port_t
 *	EDMA port types.
 */
enum nss_edma_port_t {
	NSS_EDMA_PORT_PHYSICAL,
	NSS_EDMA_PORT_VIRTUAL,
	NSS_EDMA_PORT_TYPE_MAX
};

/**
 * nss_edma_rx_ring_stats
 *	EDMA Rx ring statistics.
 */
struct nss_edma_rx_ring_stats {
	uint32_t rx_csum_err;		/**< Number of Rx checksum errors. */
	uint32_t desc_cnt;		/**< Number of descriptors processed. */
};

/**
 * nss_edma_tx_ring_stats
 *	EDMA Tx ring statistics.
 */
struct nss_edma_tx_ring_stats {
	uint32_t tx_err;		/**< Number of Tx errors. */
	uint32_t tx_dropped;		/**< Number of Tx dropped packets. */
	uint32_t desc_cnt;		/**< Number of descriptors processed. */
};

/**
 * nss_edma_rxfill_ring_stats
 *	EDMA Rx fill ring statistics.
 */
struct nss_edma_rxfill_ring_stats {
	uint32_t desc_cnt;		/**< Number of descriptors processed. */
};

/**
 * nss_edma_txcmpl_ring_stats
 *	EDMA Tx complete ring statistics.
 */
struct nss_edma_txcmpl_ring_stats {
	uint32_t desc_cnt;		/**< Number of descriptors processed. */
};

/**
 * nss_edma_port_stats
 *	EDMA port statistics.
 */
struct nss_edma_port_stats {
	struct nss_cmn_node_stats node_stats;	/**< Common node statistics. */
	enum nss_edma_port_t port_type;		/**< Type of port. */
	uint16_t edma_rx_ring;			/**< Rx ring statistics. */
	uint16_t edma_tx_ring;			/**< Tx ring statistics. */
};

/**
 * nss_edma_port_stats_sync
 *	Synchronized EDMA port statistics.
 */
struct nss_edma_port_stats_sync {
	uint16_t start_port;		/**< Starting index of the subset. */
	uint16_t end_port;		/**< Ending index of the subset. */
	struct nss_edma_port_stats port_stats[];
					/**< Subset of EDMA port statistics. */
};

/**
 * nss_edma_ring_stats_sync
 *	Synchronized EDMA ring statistics.
 */
struct nss_edma_ring_stats_sync {
	struct nss_edma_tx_ring_stats tx_ring[NSS_EDMA_NUM_TX_RING_MAX];
			/**< EDMA Tx ring statistics. */
	struct nss_edma_rx_ring_stats rx_ring[NSS_EDMA_NUM_RX_RING_MAX];
			/**< EDMA Rx ring statistics. */
	struct nss_edma_txcmpl_ring_stats txcmpl_ring[NSS_EDMA_NUM_TXCMPL_RING_MAX];
			/**< EDMA Tx complete ring statistics. */
	struct nss_edma_rxfill_ring_stats rxfill_ring[NSS_EDMA_NUM_RXFILL_RING_MAX];
			/**< EDMA Rx fill ring statistics. */
};

/**
 * nss_edma_msg
 *	Data for sending and receiving EDMA messages (to synchronize with
 *	the firmware EDMA).
 */
struct nss_edma_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of an EDMA message.
	 */
	union {
		struct nss_edma_port_stats_sync port_stats;
				/**< Synchronized port statistics. ??is this comment correct? */
		struct nss_edma_ring_stats_sync ring_stats;
				/**< Synchronized ring statistics. ??is this comment correct? */
	} msg;			/**< Message payload. ??is this comment correct? I assumed it's the message payload because the first field is the message header */
};

#ifdef __KERNEL__ /* only kernel will use. ??do you want the following in the PDF?*/

/**
 * Callback function for receiving EDMA messages.
 *
 * @datatypes
 * nss_edma_msg
 *
 * @param[in] app_data  Pointer to the application context for this message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_edma_msg_callback_t)(void *app_data, struct nss_edma_msg *msg);

/**
 * nss_edma_notify_register
 *	Registers a callback notifier with the NSS for sending and receiving messages.
 *
 * @datatypes
 * nss_edma_msg_callback_t
 *
 * @param[in] cb        Callback function for the message.
 * @param[in] app_data  Pointer to the application context for this message.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_edma_notify_register(nss_edma_msg_callback_t cb, void *app_data);

/**
 * nss_edma_notify_unregister
 *	Deregisters a callback notifier from the NSS.
 *
 * @return
 * None.
 *
 * @dependencies
 * The callback notifier must have been previously registered.
 */
extern void nss_edma_notify_unregister(void);

#endif /* __KERNEL__ */

/**
 * @}
 */

#endif /* __NSS_EDMA_H */

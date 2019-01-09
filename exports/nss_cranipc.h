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
 * @file nss_cranipc.h
 *	NSS CRANIPC interface definitions.
 */

#ifndef __NSS_CRANIPC_H
#define __NSS_CRANIPC_H

#define NSS_CRANIPC_IP_VER_V4 0x00000001
#define NSS_CRANIPC_IP_VER_V6 0x00000002

/* Jumbo MRU default value for enabling C-RAN */
#define NSS_CRANIPC_JUMBO_MRU_DEFAULT 10000

/**
 * nss_cranipc_message_type
 *	CRANIPC Message type.
 *
 */
enum nss_cranipc_msg_type {
	NSS_CRANIPC_MSG_TYPE_NONE,
	NSS_CRANIPC_MSG_TYPE_CONFIG,
	NSS_CRANIPC_MSG_TYPE_STATS_SYNC,
	NSS_CRANIPC_MSG_TYPE_MAX,
};

/**
 * nss_cranipc_confiig
 *	CRANIPC config tuple information.
 */
struct nss_cranipc_config {
	uint32_t sip[4];	/**< Source IP . sip[0] has IP in case of v4*/
	uint32_t dip[4];	/**< Dest IP . dip[0] has IP in case of v6 */
	uint16_t sport;		/**< Source UDP Port. */
	uint16_t dport;		/**< Destination UDP Port. */
	uint32_t flags;		/**Determines if config is v4 or v6 */
};

/**
 * nss_cranipc_error_response_type
 *	Error types for CRANIPC messages.
 */
enum nss_cranipc_error_response_type {
	NSS_CRANIPC_UNKNOWN_MSG_TYPE = 1,
	NSS_CRANIPC_LAST
};

/**
 * nss_cranipc_node_sync
 *	CRANIPC node synchronization statistics.
 */
struct nss_cranipc_node_sync {
	struct nss_cmn_node_stats node_stats; 	/**< Common node statistics. */

	/* Stats in DL direction */
	uint32_t dl_ipc;			/**< Number of IPC ptrs pushed for Q6 to DL M FIFO. */
	uint32_t dl_returned_ipc;		/**< Number of ipc ptrs released by Q6 to DL B FIFO */
	uint32_t dl_buffers_in_use;		/**< dl_ipc - dl_returned_ipc */
	uint32_t dl_lowest_latency;		/**< Lowest latency. */
	uint32_t dl_highest_latency;		/**< Highest latency. */
	uint32_t dl_270us_pkts;			/**< Number of packets having latency greater
						     than 270 microseconds. */
	uint32_t dl_queue_dropped;		/**< Number of queue dropped Packets. */
	uint32_t dl_dropped_not_ready;		/**< Number of packets dropped due to not active state */

	/* Stats in UL direction */
	uint32_t ul_ipc;			/**< Number of IPC ptrs pushed for Q6 to UL B FIFO */
	uint32_t ul_returned_ipc;		/**< Number of IPC/PBUFS returned to payload_mgr */
	uint32_t ul_buffers_in_use;		/**< ul_returned_ipc - ul_ipc*/
	uint32_t ul_lowest_latency;		/**< Lowest latency. */
	uint32_t ul_highest_latency;		/**< Highest latency. */
	uint32_t ul_payload_alloc_fails;	/**< Number failed pbuf allocations */
};

/**
 * nss_cranipc_config_msg
 *	CRANIPC Config message.
 */
struct nss_cranipc_msg {
	struct nss_cmn_msg cm;
	union {
		struct nss_cranipc_config config;
		struct nss_cranipc_node_sync stats;
	}msg;
};

#ifdef __KERNEL__ /* only kernel will use. */

/**
 * Callback function for receiving CRANIPC data.
 *
 * @datatypes
 * net_device \n
 * sk_buff \n
 * napi_struct
 *
 * @param[in] dev	Pointer to the associated netdev
 * @param[in] skb	Pointer to the data skb.
 * @param[in] napi	Pointer to the NAPI structure
 */
typedef void (*nss_cranipc_callback_t)(struct net_device *dev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * Callback function for receiving CRANIPC messages.
 *
 * @datatypes
 * nss_cranipc_msg
 *
 * @param[in] app_data	Pointer to the application context of the message.
 * @param[in] msg	Pointer to the message data.
 */
typedef void (*nss_cranipc_msg_callback_t)(void *app_data, struct nss_cranipc_msg *msg);

/**
 * Callback function for receiving CRANIPC event.
 *
 * @datatypes
 * nss_cranipc_msg
 *
 * @param[in] app_data	Pointer to the application context of the message.
 * @param[in] msg	Pointer to the message data.
 */
typedef void (*nss_cranipc_event_callback_t)(void *app_data, struct nss_cranipc_msg *msg);

/**
 * nss_cranipc_tx
 *	Transmits an cranipc message to the NSS.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_cranipc_msg
 *
 * @param[in] nss_ctx	Pointer to the NSS context.
 * @param[in] msg	Pointer to the message data.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_cranipc_tx(struct nss_ctx_instance *nss_ctx, struct nss_cranipc_msg *msg);

/**
 * nss_cranipc_notify_register
 *	Registers a notifier callback to forward the cranipc messages received from the NSS
 *	firmware to the registered subsystem.
 *
 * @datatypes
 * nss_cranipc_msg_callback_t
 *
 * @param[in] cb        Callback function for the message.
 * @param[in] app_data  Pointer to the application context of the message.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_cranipc_notify_register(nss_cranipc_msg_callback_t cb, void *app_data);

/**
 * nss_cranipc_is_cran_enabled
 *	check whether CRAN is enabled or not.
 *
 * @return
 * bool.
 *
 * @dependencies
 * The callback notifier must have been previously registered.
 */
extern bool nss_cranipc_is_cran_enabled(void);

/**
 * nss_cranipc_notify_unregister
 *	Unregisters an CRANIPC message notifier callback from the NSS.
 */
extern void nss_cranipc_notify_unregister(void);

/**
 * nss_cranipc_register_handler
 *	Registers the cranipc message handler.
 *
 * @return
 * None.
 */
extern void nss_cranipc_register_handler(void);

/**
 * nss_register_cranipc_if
 *	Register the interface with the NSS FW along with callbacks
 *
 * @datatypes
 * nss_cranipc_callback_t
 * nss_cranipc_event_callback_t
 *
 * @param[in] if_num	Interface number
 * @param[in] cranipc_cb  callback for cranipc data
 * @param[in] cranipc_ev_cb  callback for cranipc event
 *
 * @return
 * None
 */
extern void *nss_register_cranipc_if(uint32_t if_num, nss_cranipc_callback_t cranipc_cb,
				     nss_cranipc_event_callback_t cranipc_ev_cb,
				     struct net_device *netdev);

/**
 * nss_unregister_cranipc_if
 *	Unregister the interface with the NSS FW along with callbacks
 *
 * @datatypes
 *
 * @param[in] if_num	Interface number
 *
 * @return
 * None
 */
extern void nss_unregister_cranipc_if(uint32_t if_num);

/**
 * nss_cranipc_config
 *	Send the config message to NSS-FW pkg cranipc
 *
 * @datatypes
 * nss_cranipc_msg
 *
 * @param[in] msg	Config message from nlcfg
 *
 * @return
 * None
 */
extern int nss_cranipc_config(struct nss_cranipc_msg *msg);

/**
 * nss_cranipc_msg_init
 *	Initializes CRANIPC messages.
 *
 * @datatypes
 * nss_cranipc_msg \n
 * nss_cranipc_msg_callback_t
 *
 * @param[in,out] nim	Pointer to the NSS interface message.
 * @param[in]	if_num	NSS interface number.
 * @param[in]	type	Type of message.
 * @param[in]	len	Size of the payload.
 * @param[in]	cb	Callback function for the message.
 * @param[in]	app_data Pointer to the application context of the message.
 *
 * @return
 * None.
 */
extern void nss_cranipc_msg_init(struct nss_cranipc_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
			nss_cranipc_msg_callback_t cb, void *app_data);

/**
 * nss_cranipc_sync_update
 * 	Update the stats sync message to local data structure.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_cranipc_node_sync
 *
 * @param[in] nss_ctx	Pointer to the NSS context.
 * @param[in] stats	Pointer to the stats message from NSS.
 *
 * @return
 * None.
 */
extern void nss_cranipc_sync_update(struct nss_ctx_instance *nss_ctx, struct nss_cranipc_node_sync *stats);

/**
 * nss_cranipc_get_context
 *	Get cran nss context
 *
 * @datatypes
 * None
 *
 * @param[in/out]	None
 *
 * @return
 * nss_ctx_instance
 */
extern struct nss_ctx_instance *nss_cranipc_get_context(void);
#endif /*__KERNEL__ */

/**
 * @}
 */

#endif /* __NSS_CRANIPC_H */

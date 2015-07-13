/*
 **************************************************************************
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
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
  * nss_wifi.h
  * 	NSS TO HLOS interface definitions.
  */

#ifndef __NSS_WIFI_H
#define __NSS_WIFI_H

#define NSS_WIFI_MGMT_DATA_LEN  128
#define NSS_WIFI_RAWDATA_MAX_LEN  64

/**
 * wifi interface request/response types
 */
enum nss_wifi_metadata_types {
	NSS_WIFI_INIT_MSG,
	NSS_WIFI_POST_RECV_MSG,
	NSS_WIFI_HTT_INIT_MSG,
	NSS_WIFI_TX_INIT_MSG,
	NSS_WIFI_RAW_SEND_MSG,
	NSS_WIFI_MGMT_SEND_MSG,
	NSS_WIFI_WDS_PEER_ADD_MSG,
	NSS_WIFI_WDS_PEER_DEL_MSG,
	NSS_WIFI_STOP_MSG,
	NSS_WIFI_RESET_MSG,
	NSS_WIFI_STATS_MSG,
	NSS_WIFI_MAX_MSG
};

/*
 * wifi msg error types
 */
enum wifi_error_types {
	NSS_WIFI_EMSG_NONE = 0,
	NSS_WIFI_EMSG_UNKNOWN,
	NSS_WIFI_EMSG_MGMT_DLEN,		/**< invalid management data length */
	NSS_WIFI_EMSG_MGMT_SEND,		/**< error in sending management data */
	NSS_WIFI_EMSG_CE_INIT_FAIL,		/**< error in ce init */
	NSS_WIFI_EMSG_PDEV_INIT_FAIL,		/**< error in pdev init */
	NSS_WIFI_EMSG_HTT_INIT_FAIL,		/**< error in htt dev init */
	NSS_WIFI_EMSG_PEER_ADD,			/**< error in wds peer add */
	NSS_WIFI_EMSG_TARGET_NOT_SUPPORTED,	/**< invalid traget type passed */
	NSS_WIFI_EMSG_STATE_NOT_RESET,		/**< reset failed */
	NSS_WIFI_EMSG_STATE_NOT_INIT_DONE,	/**< init failed */
	NSS_WIFI_EMSG_STATE_NULL_CE_HANDLE,	/**< invalid ce handle */
	NSS_WIFI_EMSG_STATE_NOT_CE_READY,	/**< ce is not ready */
	NSS_WIFI_EMSG_STATE_NOT_HTT_READY,	/**< htt is not ready */
};

/*
 * Copy engine ring internal state
 */
struct nss_wifi_ce_ring_state_msg {
	uint32_t nentries;			/**< Number of entries in the CE ring */
	uint32_t nentries_mask;			/**< Number of entry mask */
	uint32_t sw_index;			/**< Initial SW index start*/
	uint32_t write_index;			/**< Initial write index start */
	uint32_t hw_index;			/**< Initial h/w index */
	uint32_t base_addr_CE_space;		/**< CE h/w ring physical address */
	uint32_t base_addr_owner_space;		/**< CE h/w ring virtual  address */
};

/**
 *  Copy engine internal state
 */
struct nss_wifi_ce_state_msg {
	struct nss_wifi_ce_ring_state_msg src_ring;
						/**< Source ring info */
	struct nss_wifi_ce_ring_state_msg dest_ring;
						/**< Destination ring info */
	uint32_t ctrl_addr;			/**< Relative to BAR */
};

/**
 * wifi init message
 */
struct nss_wifi_init_msg {
	uint32_t radio_id ;			/**< Radio index */
	uint32_t pci_mem;			/**< PCI memory  address */
	uint32_t target_type;			/**< WiFi Target type */
	uint32_t mu_mimo_enhancement_en;        /**< enable mu mimo enhancement */
	struct nss_wifi_ce_state_msg ce_tx_state;
						/**< Transmit CE info */
	struct nss_wifi_ce_state_msg ce_rx_state;
						/**< Recieve CE info */
};

/**
 * wifi htt init configuration data
 */
struct nss_wifi_htt_init_msg {
	uint32_t radio_id;			/**< Radio Index */
	uint32_t ringsize;			/**< WLAN h/w mac ring size */
	uint32_t fill_level;			/**< Initial fill_level */
	uint32_t paddrs_ringptr;		/**< Phyical address of WLAN mac h/w ring */
	uint32_t paddrs_ringpaddr;		/**< Virtual  address of WLAN mac h/w ring */
	uint32_t alloc_idx_vaddr;		/**< Virtual addres of h/w Ring Index */
	uint32_t alloc_idx_paddr;		/**< Physical address of h/w ring index */
};

/**
 * wifi tx init configuration data
 */
struct nss_wifi_tx_init_msg {
	uint32_t radio_id;			/**< Radio Index */
	uint32_t desc_pool_size;		/**< Number of descripor  pool allocated */
	uint32_t tx_desc_array;			/**< Host initialized s/w wlan desc pool memory */
	uint32_t wlanextdesc_addr;		/**< WLAN Mac Extenstion descriptor pool starting address*/
	uint32_t wlanextdesc_size;		/**< WLAN Mac Extenstion descriptor size*/
	uint32_t htt_tx_desc_base_vaddr;	/**< Firmware shared HTT trasmit desc memory start virtual addres */
	uint32_t htt_tx_desc_base_paddr; 	/**< Firmware shared HTT trasmit desc memory start physical address */
	uint32_t htt_tx_desc_offset; 		/**< Firmware shared HTT trasmit each desc size */
	uint32_t pmap_addr;			/**< Firmware shared peer/TID map */
};

/**
 * wifi raw data send message structure
 */
struct nss_wifi_rawsend_msg {
	uint32_t radio_id ;			/**< Radio Index */
	uint32_t len;				/**< Length of the raw data */
	uint32_t array[NSS_WIFI_RAWDATA_MAX_LEN];
						/**< Raw data */
};

/**
 *  wifi management data message structure
 */
struct nss_wifi_mgmtsend_msg {
	uint32_t desc_id;			/**< Radio Index */
	uint32_t len;				/**< Length of the management data */
	uint8_t array[NSS_WIFI_MGMT_DATA_LEN];
						/**< Management data */
};

/**
 * wifi pdev wds peer specific messages
 */
struct nss_wifi_wds_peer_msg {
	uint8_t dest_mac[ETH_ALEN];		/**< Mac address of destination */
	uint8_t reserved[2];
	uint8_t peer_mac[ETH_ALEN];		/**< Mac address of base peer */
	uint8_t reserved1[2];
};

/**
 * wifi reset message
 */
struct nss_wifi_reset_msg {
	uint32_t radio_id;			/**< Radio index */
};

/**
 * wifi stop message
 */
struct nss_wifi_stop_msg {
	uint32_t radio_id;			/**< Radio index */
};

/**
 * wifi statistics sync message structure.
 */
struct nss_wifi_stats_sync_msg {
	struct nss_cmn_node_stats node_stats;	/**< node statistics */
	uint32_t tx_transmit_dropped;           /**< number of packets dropped during transmission */
	uint32_t tx_transmit_completions;       /**< number of packets for which transmission completion received */
	uint32_t tx_mgmt_rcv_cnt;               /**< number of management packets received from host for transmission */
	uint32_t tx_mgmt_pkts;                  /**< number of management packets transmitted over wifi */
	uint32_t tx_mgmt_dropped;               /**< number of management packets dropped because of transmission failure */
	uint32_t tx_mgmt_completions;           /**< number of management packets for which tx completions are received */
	uint32_t tx_inv_peer_enq_cnt;           /**< number of packets for which tx enqueue failed because of invalid peer */
	uint32_t rx_inv_peer_rcv_cnt;           /**< number of packets received from wifi with invalid peer id */
	uint32_t rx_pn_check_failed;            /**< number of rx packets which failed packet number check */
	uint32_t rx_pkts_deliverd;              /**< number of rx packets that NSS wifi driver could successfully process */
};

/**
 * Message structure to send/receive wifi messages
 */
struct nss_wifi_msg {
	struct nss_cmn_msg cm;			/**< Message Header */
	union {
		struct nss_wifi_init_msg initmsg;
		struct nss_wifi_stop_msg stopmsg;
		struct nss_wifi_reset_msg resetmsg;
		struct nss_wifi_htt_init_msg httinitmsg;
		struct nss_wifi_tx_init_msg pdevtxinitmsg;
		struct nss_wifi_rawsend_msg rawmsg;
		struct nss_wifi_mgmtsend_msg mgmtmsg;
		struct nss_wifi_wds_peer_msg pdevwdspeermsg;
		struct nss_wifi_stats_sync_msg statsmsg;
	} msg;
};

/**
 * @brief Send wifi messages
 *
 * @param nss_ctx NSS context
 * @param msg NSS wifi message
 *
 * @return nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_wifi_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_wifi_msg *msg);

/**
 * @brief Callback to receive wifi messages
 *
 * @param app_data Application context of the message
 * @param msg Message data
 *
 * @return void
 */
typedef void (*nss_wifi_msg_callback_t)(void *app_data, struct nss_wifi_msg *msg);

/**
 * @brief Callback to receive wifi data
 *
 * @param app_data Application context of the message
 * @param os_buf  Pointer to data buffer
 *
 * @return void
 */
typedef void (*nss_wifi_callback_t)(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * @brief Register to send/receive wifi messages to NSS
 *
 * @param if_num NSS interface number
 * @param wifi_callback Callback for wifi data
 * @param msg_callback Callback for wifi messages
 * @param netdev netdevice associated with the wifi
 *
 * @return nss_ctx_instance* NSS context
 */
struct nss_ctx_instance *nss_register_wifi_if(uint32_t if_num, nss_wifi_callback_t wifi_callback,
			nss_wifi_callback_t wifi_ext_callback, nss_wifi_msg_callback_t event_callback, struct net_device *netdev, uint32_t features);

/**
 * @brief Unregister wifi interface with NSS
 *
 * @param if_num NSS interface number
 *
 * @return void
 */
void nss_unregister_wifi_if(uint32_t if_num);
#endif /* __NSS_WIFI_H */

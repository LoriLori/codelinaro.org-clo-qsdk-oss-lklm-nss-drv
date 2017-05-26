/*
 **************************************************************************
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
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

 /**
  * @file nss_wifili.h
  *	NSS TO HLOS interface definitions.
  */
#ifndef __NSS_WIFILI_H
#define __NSS_WIFILI_H

#define NSS_WIFILI_MAX_SRNG_REG_GROUPS_MSG 2
				/**< Max srng register groups. */
#define NSS_WIFILI_MAX_NUMBER_OF_PAGE_MSG 32
				/**< Max number of pages allocated from host. */
#define NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG 4
				/**< Max number of tcl data ring for NSS. */
#define NSS_WIFILI_MAX_REO_DATA_RINGS_MSG 4
				/**< Max number of reo data ring for NSS. */
#define NSS_WIFILI_SOC_PER_PACKET_METADATA_OFFSET 4
				/**< Metadata area for storing rx stats. */

/**
 * nss_wifili_msg_types
 *	nss_wifili messages
 */
enum nss_wifili_msg_types {
	NSS_WIFILI_INIT_MSG = 0,
	NSS_WIFILI_SOC_RESET_MSG,
	NSS_WIFILI_PDEV_INIT_MSG,
	NSS_WIFILI_PDEV_DEINIT_MSG,
	NSS_WIFILI_START_MSG,
	NSS_WIFILI_STOP_MSG,
	NSS_WIFILI_PEER_CREATE_MSG,
	NSS_WIFILI_PEER_DELETE_MSG,
	NSS_WIFILI_SEND_PEER_MEMORY_REQUEST_MSG,
	NSS_WIFILI_PEER_FREELIST_APPEND_MSG,
	NSS_WIFILI_PDEV_STATS_SYNC_MSG,
	NSS_WIFILI_MAX_MSG
};

/**
 * wifili_error_types
 *	wifili msg error types
 */
enum wifili_error_types {
	NSS_WIFILI_EMSG_NONE = 0,
			/**< no error */
	NSS_WIFILI_EMSG_RINGS_INIT_FAIL,
			/**< device ring initialization fail */
	NSS_WIFILI_EMSG_PDEV_INIT_IMPROPER_STATE_FAIL,
			/**< radio init fail due to improper state of device */
	NSS_WIFILI_EMSG_PDEV_INIT_INVALID_RADIOID_FAIL,
			/**< radio init failed due to invalid radio id */
	NSS_WIFILI_EMSG_PDEV_RESET_INVALID_RADIOID_FAIL,
			/**< radio reset failed due to invalid radio id */
	NSS_WIFILI_EMSG_START_IMPROPER_STATE_FAIL,
			/**< device start fail due to improper state */
	NSS_WIFILI_EMSG_PEER_CREATE_FAIL,
			/**< peed creat fail */
	NSS_WIFILI_EMSG_PEER_DELETE_FAIL,
			/**< peer delete fail */
	NSS_WIFILI_EMSG_HASHMEM_INIT_FAIL,
			/**< peer hash mem init fail */
	NSS_WIFILI_EMSG_PEER_FREELIST_APPEND_FAIL,
			/**< peer freelist append fail*/
	NSS_WIFILI_EMSG_PEER_CREATE_INVALID_VDEVID_FAIL,
			/**< peer create fail due to invalide vdev_id */
	NSS_WIFILI_EMSG_PEER_CREATE_INVALID_PEER_ID_FAIL,
			/**< peer create fail due to invalide peer_id */
	NSS_WIFILI_EMSG_PEER_CREATE_VDEV_NULL_FAIL,
			/**< peer create fail due to vdev null */
	NSS_WIFILI_EMSG_PEER_CREATE_PDEV_NULL_FAIL,
			/**< peer create fail due to peer null */
	NSS_WIFILI_EMSG_PEER_CREATE_ALLOC_FAIL,
			/**< peer create fail due to mem alloc fail */
	NSS_WIFILI_EMSG_PEER_DELETE_VAPID_INVALID_FAIL,
			/**< peer delete fail due to invalide vdev_id */
	NSS_WIFILI_EMSG_PEER_DELETE_INVALID_PEERID_FAIL,
			/**< peer delete fail due to invalide peer_id */
	NSS_WIFILI_EMSG_PEER_DELETE_VDEV_NULL_FAIL,
			/**< peer delete fail due to vdev null */
	NSS_WIFILI_EMSG_PEER_DELETE_PDEV_NULL_FAIL,
			/**< peer create fail due to pdev null */
	NSS_WIFILI_EMSG_PEER_DELETE_PEER_NULL_FAIL,
			/**< peer create fail due to peer null */
	NSS_WIFILI_EMSG_PEER_DELETE_PEER_CORRUPTED_FAIL,
			/**< peer create fail due to corrupted peer  */
	NSS_WIFILI_EMSG_GROUP0_TIMER_ALLOC_FAIL,
			/**< timer alloc fail */
	NSS_WIFILI_EMSG_INSUFFICIENT_WT_FAIL,
			/**< insufficient worker thread error */
	NSS_WIFILI_EMSG_INVALID_NUM_TCL_RING_FAIL,
			/**< invlalid number of tcl ring provided in init msg */
	NSS_WIFILI_EMSG_INVALID_NUM_REO_DST_RING_FAIL,
			/**< invalid number of reo dst ring in init msg */
	NSS_WIFILI_EMSG_HAL_SRNG_SOC_ALLOC_FAIL,
			/**< srng soc memory allocation failure */
	NSS_WIFILI_EMSG_HAL_TCL_SRNG_ALLOC_FAIL,
			/**< tcl srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_TXCOMP_SRNG_ALLOC_FAIL,
			/**< txcomp srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_REODST_SRNG_ALLOC_FAIL,
			/**< reo dst srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_REOREINJECT_SRNG_ALLOC_FAIL,
			/**< reo reinject srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_RXRELEASE_SRNG_ALLOC_FAIL,
			/**< rx release srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_RXEXCP_SRNG_ALLOC_FAIL,
			/**< rx exception srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_TX_MEMALLOC_FAIL,
			/**< tx hal srng ring alloc fail */
	NSS_WIFILI_EMSG_HAL_TX_INVLID_POOL_NUM_FAIL,
			/**< invalid pool num in init msg  */
	NSS_WIFILI_EMSG_HAL_TX_INVALID_PAGE_NUM_FAIL,
			/**< invalid page num in init msg  */
	NSS_WIFILI_EMSG_HAL_TX_DESC_MEM_ALLOC_FAIL,
			/**< tx desc mem allocation fail  */
	NSS_WIFILI_EMSG_HAL_RX_MEMALLOC_FAIL,
			/**< rx memalloc fail */
	NSS_WIFILI_EMSG_UNKNOWN
			/**< unknown error message */
};

/**
 * wifili_soc_extended_data_types
 *	enumeration of extended data type to host
 */
enum wifili_soc_extended_data_types {
	WIFILI_SOC_EXT_DATA_PKT_TYPE_NONE,
	WIFILI_SOC_EXT_DATA_PKT_MSDU_LINK_DESC,
	WIFILI_SOC_EXT_DATA_PKT_TYPE_MAX
};

/**
 * nss_wifili_hal_srng_info
 *	wifili hal srng info
 */
struct nss_wifili_hal_srng_info{
	uint8_t ring_id;
			/**< ring id */
	uint8_t mac_id;
			/**< pdev id */
	uint8_t resv[2];
	uint32_t ring_base_paddr;
			/**< physical base address of the ring */
	uint32_t num_entries;
			/**< number of entries in ring */
	uint32_t flags;	/**< misc flags */
	uint32_t ring_dir;
			/**< ring direction: source or dest */
	uint32_t entry_size;
			/**< ring entry size */
	uint32_t low_threshold;
			/**< Low threshold – in number of ring entries (valid for src rings only) */
	uint32_t hwreg_base[NSS_WIFILI_MAX_SRNG_REG_GROUPS_MSG];
			/**< hw ring base address */
};

/**
 * nss_wifili_hal_srng_soc_msg
 *	wifi li hal srng message
 */
struct nss_wifili_hal_srng_soc_msg {
	uint32_t dev_base_addr;
			/**< base address of wlan dev */
	uint32_t shadow_rdptr_mem_addr;
			/**< shadow rdptr address */
	uint32_t shadow_wrptr_mem_addr;
			/**< shadow wrptr address */
};

/**
 * nss_wifili_tx_desc_init_msg
 *	wifi li software desc pool init msg
 */
struct nss_wifili_tx_desc_init_msg {
	uint32_t num_tx_desc;
			/**< count of the sw descriptors */
	uint32_t num_tx_desc_ext;
			/**< count of sw extention descriptors */
	uint32_t num_pool;
			/**< number of descriptor pools */
	uint32_t memory_addr[NSS_WIFILI_MAX_NUMBER_OF_PAGE_MSG];
			/**< memory start address of each page */
	uint32_t memory_size[NSS_WIFILI_MAX_NUMBER_OF_PAGE_MSG];
			/**< memory size */
	uint32_t num_memaddr;
			/**< number of mem address */
	uint32_t ext_desc_page_num;
			/**< ext_desc_page number */
};

/**
 * nss_wifili_init_msg
 *	Lithium soc init msg
 */
struct nss_wifili_init_msg {
	struct nss_wifili_hal_srng_soc_msg hssm;
	uint8_t num_tcl_data_rings;
			/**< number of tcl data rings */
	uint8_t num_reo_dest_rings;
			/**< number of reo rings */
	uint8_t resv[2];
			/**< reserve for alignment */
	struct nss_wifili_hal_srng_info tcl_ring_info[NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG];
			/**< tcl data ring config info */
	struct nss_wifili_hal_srng_info tx_comp_ring[NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG];
			/**< tx completion ring config info */
	struct nss_wifili_hal_srng_info reo_dest_ring[NSS_WIFILI_MAX_REO_DATA_RINGS_MSG];
			/**< reo destination ring config info */
	struct nss_wifili_hal_srng_info reo_exception_ring;
			/**< reo exception ring config info */
	struct nss_wifili_hal_srng_info rx_rel_ring;
			/**< wbm release ring config info */
	struct nss_wifili_hal_srng_info reo_reinject_ring;
			/**< reinject ring config info */
	struct nss_wifili_tx_desc_init_msg wtdim;
			/**< tx descriptor init message */
};

/**
 * nss_wifili_pdev_deinit_msg
 *	li pdev deinit msg
 */
struct nss_wifili_pdev_deinit_msg {
	uint32_t ifnum;	/**< nss ifnum of pdev */
};

/**
 * nss_wifili_pdev_init_msg
 *	li pdev init msg
 */
struct nss_wifili_pdev_init_msg {
	struct nss_wifili_hal_srng_info rxdma_ring;
			/**< mac ring configuration */
	uint32_t radio_id;
			/**< mac radio id */
	uint32_t hwmode;
			/**< mac hw mode */
};

/**
 * nss_wifili_peer_msg
 *	wifili peer create message.
 */
struct nss_wifili_peer_msg {
	uint8_t peer_mac_addr[6];
			/**< peer mac address */
	uint16_t vdev_id;
			/**< vap id */
	uint16_t peer_id;
			/**< peer id */
	uint16_t hw_ast_idx;
			/**< hw address search table index */
};

/**
 * nss_wifili_peer_freelist_append_msg
 *	peer memory request
 */
struct nss_wifili_peer_freelist_append_msg {
	uint32_t addr;
			/**< starting address of peer_freelist pool */
	uint32_t length;
			/**< length of peer_freelist pool */
	uint32_t num_peers;
			/**< max number of peer entries supported in pool */
};

/**
 * nss_wifili_tx_stats
 *	tx statistics
 */
struct nss_wifili_tx_stats {
	uint32_t tx_enqueue_dropped;
			/**< tx enqueue drop count */
	uint32_t tx_enqueue_cnt;
			/**< tx enqueue succesful count */
	uint32_t tx_dequeue_cnt;
			/**< tx dequeue count */
	uint32_t tx_dequeue_drop;
			/**< drop count for dequeue */
	uint32_t tx_send_fail_cnt;
			/**< hw send fail count */
	uint32_t tx_completion_cnt;
			/**< tx completion count */
	uint32_t tx_desc_in_use;
			/**< tx desc in use count */
};

/**
 * nss_wifili_rx_stats
 *	rx statistics
 */
struct nss_wifili_rx_stats {
	uint32_t rx_desc_alloc_fail;
			/**< rx desc alloc fail count */
	uint32_t rx_msdu_err;
			/**< rx msdu error count */
	uint32_t rx_inv_peer;
			/**< rx invalid peer count */
	uint32_t rx_scatter_inv_peer;
			/**< rx scatter invalid peer count */
	uint32_t rx_wds_learn_send;
			/**< wds src port learn packet */
	uint32_t rx_wds_learn_send_fail;
			/**< wds src port learn exception send fail cnt */
	uint32_t rx_ring_error;
			/**< rx ring error count */
	uint32_t rx_send_dropped;
			/**< rx send dropped count */
	uint32_t rx_deliver_cnt;
			/**< rx deliver count */
};

/**
 * nss_wifili_stats_sync_msg
 *	li stats sync msg
 */
struct nss_wifili_stats_sync_msg {
	struct nss_wifili_tx_stats tx_stats;
			/**< transmit statistics */
	struct nss_wifili_rx_stats rx_stats;
			/**< receive statistics */
};

/**
 * wifili_soc_linkdesc_per_packet_metadata
 *	linkdesc per packet metadata
 */
struct wifili_soc_linkdesc_per_packet_metadata
{
	uint32_t desc_addr;	/**< link descriptor address */
};

/**
 * wifili_soc_per_packet_metadata
 *	Per packet special data that has to be sent to host
 */
struct wifili_soc_per_packet_metadata {
	uint32_t pkt_type;
	union {
		struct wifili_soc_linkdesc_per_packet_metadata linkdesc_metadata;
	} metadata;
};

/**
 * nss_wifili_msg
 *	Structure that describes wifi li messages
 */
struct nss_wifili_msg {
	struct nss_cmn_msg cm;                  /**< Common message Header */
	union {
		struct nss_wifili_init_msg init;
				/**< Wi-Fi initialization data. */
		struct nss_wifili_pdev_init_msg pdevmsg;
				/**< Tx initialization data. */
		struct nss_wifili_pdev_deinit_msg pdevdeinit;
				/**< Tx de-initialization data. */
		struct nss_wifili_peer_msg peermsg;
				/**< Peer-specific data for the physical device. */
		struct nss_wifili_peer_freelist_append_msg peer_freelist_append;
				/**< Information for creating a peer freelist. */
		struct nss_wifili_stats_sync_msg wlsoc_stats;
				/**< Synchronization statistics. */
	} msg;
};

/**
 * nss_wifili_tx_msg
 *	Send wifili messages
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_wifili_msg
 *
 * @param[in] nss_ctx NSS context.
 * @param[in] msg     NSS wifi message.
 *
 * @return
 * nss_tx_status_t Tx status
 */
extern nss_tx_status_t nss_wifili_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_wifili_msg *msg);

/**
 * nss_wifili_msg_callback_t
 *	Callback to receive wifili messages
 *
 * @datatypes
 * nss_wifili_msg
 *
 * @param[in] app_data Application context of the message.
 * @param[in] msg      Message data.
 *
 * @return
 * void
 */
typedef void (*nss_wifili_msg_callback_t)(void *app_data, struct nss_wifili_msg *msg);

/**
 * nss_wifili_callback_t
 *	Callback to receive wifi data
 *
 * @datatypes
 * net_device \n
 * sk_buff \n
 * napi_struct
 *
 *
 * @param[in] netdev  Pointer to the associated network device.
 * @param[in] skb     Pointer to the data socket buffer.
 * @param[in] napi    Pointer to the NAPI structure.
 *
 * @return
 * void
 */
typedef void (*nss_wifili_callback_t)(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * nss_register_wifili_if
 *	Register to send/receive wifi li soc messages to NSS
 *
 * @datatypes
 * nss_wifili_callback_t \n
 * nss_wifili_msg_callback_t \n
 * net_device
 *
 * @param[in] if_num             NSS interface number.
 * @param[in] wifi_callback      Callback for the Wi-Fi virtual device data.
 * @param[in] wifi_ext_callback  Callback for the extended data.
 * @param[in] event_callback     Callback for the message.
 * @param[in] netdev             Pointer to the associated network device.
 * @param[in] features           Data socket buffer types supported by this
 *                               interface.
 *
 * @return
 * nss_ctx_instance* NSS context
 */
struct nss_ctx_instance *nss_register_wifili_if(uint32_t if_num, nss_wifili_callback_t wifi_callback,
			nss_wifili_callback_t wifi_ext_callback, nss_wifili_msg_callback_t event_callback, struct net_device *netdev, uint32_t features);

/**
 * nss_unregister_wifili_if
 *	Unregister wifi li soc interface with NSS
 *
 * @param[in] if_num NSS interface number
 *
 * @return
 * void
 */
void nss_unregister_wifili_if(uint32_t if_num);

/**
 * nss_register_wifili_radio_if
 *	Register to send/receive wifi li radio messages to NSS
 *
 * @datatypes
 * nss_wifili_callback_t \n
 * nss_wifili_msg_callback_t \n
 * net_device
 *
 * @param[in] if_num             NSS interface number.
 * @param[in] wifi_callback      Callback for the Wi-Fi radio virtual device data.
 * @param[in] wifi_ext_callback  Callback for the extended data.
 * @param[in] event_callback     Callback for the message.
 * @param[in] netdev             Pointer to the associated network device.
 * @param[in] features           Data socket buffer types supported by this
 *                               interface.
 *
 * @return
 * nss_ctx_instance* NSS context
 */
struct nss_ctx_instance *nss_register_wifili_radio_if(uint32_t if_num, nss_wifili_callback_t wifi_callback,
			nss_wifili_callback_t wifi_ext_callback, nss_wifili_msg_callback_t event_callback, struct net_device *netdev, uint32_t features);

/**
 * nss_unregister_wifili_radio_if
 *	Unregister wifi li radio interface with NSS
 *
 * @param[in] if_num NSS interface number
 *
 * @return
 * void
 */
void nss_unregister_wifili_radio_if(uint32_t if_num);
#endif /* __NSS_WIFILI_H */

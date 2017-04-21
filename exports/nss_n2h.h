/*
 **************************************************************************
 * Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
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
 * nss_n2h.h
 *	NSS to HLOS interface definitions.
 */

/**
 * @file nss_n2h.h
 * @brief NSS to HLOS interface definitions.
 */

#ifndef __NSS_N2H_H
#define __NSS_N2H_H

/**
 * @addtogroup nss_n2h_subsystem
 * @{
 */

#define MAX_PAGES_PER_MSG 32	/**< Maximum number of pages per message. */

/**
 * nss_n2h_cfg_pvt
 *	NSS-to-host private data configuration.
 */
struct nss_n2h_cfg_pvt {
	struct semaphore sem;		/**< Semaphore structure. ??need more info */
	struct completion complete;	/**< Completion structure. ??need more info */
	int empty_buf_pool;		/**< Buffer pool is empty. */
	int low_water;			/**< Low watermark. ??need more info */
	int high_water;			/**< High watermark. ??need more info */
	int wifi_pool;			/**< Wi-Fi pool. ??need more info */
	int response;			/**< Response from the firmware. */
};

/**
 * nss_n2h_metadata_types
 *	Message types for NSS-to-host requests and responses.
 */
enum nss_n2h_metadata_types {
	NSS_RX_METADATA_TYPE_N2H_STATS_SYNC=0,
	NSS_TX_METADATA_TYPE_N2H_RPS_CFG,
	NSS_TX_METADATA_TYPE_N2H_EMPTY_POOL_BUF_CFG,
	NSS_TX_METADATA_TYPE_N2H_FLUSH_PAYLOADS,
	NSS_TX_METADATA_TYPE_N2H_MITIGATION_CFG,
	NSS_METADATA_TYPE_N2H_ADD_BUF_POOL,
	NSS_TX_METADATA_TYPE_SET_WATER_MARK,
	NSS_TX_METADATA_TYPE_GET_PAYLOAD_INFO,
	NSS_TX_METADATA_TYPE_N2H_WIFI_POOL_BUF_CFG,
	NSS_TX_DDR_INFO_VIA_N2H_CFG,
	NSS_METADATA_TYPE_N2H_MAX,
};

/*
 * nss_n2h_error_types
 *	NSS-to-host error types.
 */
enum nss_n2h_error_types {
	N2H_EUNKNOWN = 1,
	N2H_ALREADY_CFG,
	N2H_LOW_WATER_MIN_INVALID,
	N2H_HIGH_WATER_LESS_THAN_LOW,
	N2H_HIGH_WATER_LIMIT_INVALID,
	N2H_LOW_WATER_LIMIT_INVALID,
	N2H_WATER_MARK_INVALID,
	N2H_EMPTY_BUFFER_TOO_HIGH,
	N2H_EMPTY_BUFFER_TOO_LOW,
	N2H_MMU_ENTRY_IS_INVALID,
};

/**
 * nss_n2h_rps
 *	NSS-to-host RPS configuration. ??what is RPS?
 */
struct nss_n2h_rps {
	uint32_t enable;	/**< Enable the RPS. */
};

/**
 * nss_n2h_mitigation
 *	NSS-to-host mitigation configuration.
 */
struct nss_n2h_mitigation {
	uint32_t enable;	/**< Enable NSS MITIGATION. */
};

/**
 * nss_n2h_buf_pool
 *	NSS-to-host buffer pool configuration.
 */
struct nss_n2h_buf_pool {
	uint32_t nss_buf_page_size;	/**< Size of the buffer page. */
	uint32_t nss_buf_num_pages;	/**< Number of buffer pages. */
	void *nss_buf_pool_vaddr[MAX_PAGES_PER_MSG];
			/**< ??Description here. */
	uint32_t nss_buf_pool_addr[MAX_PAGES_PER_MSG];
			/**< ??Description here. */
};

/**
 * nss_n2h_empty_pool_buf
 *	Old way of setting the number of empty pool buffers (payloads).
 *
 * The NSS firmware sets the low watermark to n -- ring_size, and the high
 * watermark to n + ring_size.
 */
struct nss_n2h_empty_pool_buf {
	uint32_t pool_size;		/**< Empty buffer pool size. */
};

/**
 * nss_n2h_water_mark
 *	New way of setting the low and high watermarks in the NSS firmware.
 */
struct nss_n2h_water_mark {
	/**
	 * Low watermark.
	 *
	 * Set this field to 0 for the system to automatically determine the watermark.
	 */
	uint32_t low_water;

	/**
	 * High watermark.
	 *
	 * Set this field to 0 for the system to automatically determine the watermark .
	 */
	uint32_t high_water;
};

/**
 * nss_n2h_payload_info
 *	Payload configuration based on the watermark.
 */
struct nss_n2h_payload_info {
	uint32_t pool_size;	/**< Empty buffer pool size. */

	/**
	 * Low watermark.
	 *
	 * Set this field to 0 for the system to automatically determine the watermark.
	 */
	uint32_t low_water;

	/**
	 * High watermark.
	 *
	 * Set this field to 0 for the system to automatically determine the watermark.
	 */
	uint32_t high_water;
};

/**
 * nss_n2h_flush_payloads
 *	Flush payload configuration.
 */
struct nss_n2h_flush_payloads {
	uint32_t flag;		/**< ??Description here. */
};

/**
 * nss_n2h_wifi_payloads
 *	Payloads required for Wi-Fi offloading.
 */
struct nss_n2h_wifi_payloads {
	uint32_t payloads;	/**< Number of payloads. */
};

/**
 * nss_n2h_pbuf_mgr_stats
 *	Payload buffer manager statistics.
 */
struct nss_n2h_pbuf_mgr_stats {
	uint32_t pbuf_alloc_fails;	/**< Number of buffer allocation failures. */
	uint32_t pbuf_free_count;	/**< Number of buffers freed. ??is comment ok?*/
	uint32_t pbuf_total_count;	/**< Total number of buffers. ??is comment ok? */
};

/**
 * nss_n2h_stats_sync
 *	NSS-to-host synchronization statistics.
 */
struct nss_n2h_stats_sync {
	struct nss_cmn_node_stats node_stats;	/**< Common node statistics. */
	uint32_t queue_dropped;
			/**< Number of packets dropped because the PE queue is too full. ??what is PE? */
	uint32_t total_ticks;		/**< Total clock ticks spent inside the PE. */
	uint32_t worst_case_ticks;	/**< Worst case iteration of the PE in ticks. */
	uint32_t iterations;		/**< Number of iterations around the PE. */

	struct nss_n2h_pbuf_mgr_stats pbuf_ocm_stats;
			/**< OCM statistics for the payload buffer. ??what is OCM?*/
	struct nss_n2h_pbuf_mgr_stats pbuf_default_stats;
			/**< Default statistics for the payload buffer. */

	uint32_t payload_alloc_fails;	/**< Number of payload allocation failures. */
	uint32_t payload_free_count;	/**< Number of payload allocation failures. */

	uint32_t h2n_ctrl_pkts;		/**< Control packets received from the HLOS. */
	uint32_t h2n_ctrl_bytes;	/**< Control bytes received from the HLOS. */
	uint32_t n2h_ctrl_pkts;		/**< Control packets sent to the HLOS. */
	uint32_t n2h_ctrl_bytes;	/**< Control bytes sent to the HLOS. */

	uint32_t h2n_data_pkts;		/**< Data packets received from the HLOS. */
	uint32_t h2n_data_bytes;	/**< Data bytes received from the HLOS. */
	uint32_t n2h_data_pkts;		/**< Data packets sent to the HLOS. */
	uint32_t n2h_data_bytes;	/**< Data bytes sent to the HLOS. */
	uint32_t tot_payloads;		/**< Total number of payloads in the NSS firmware. */

	/**
	 * Number of data packets with invalid interface received from the host.
	 */
	uint32_t data_interface_invalid;
};

/**
 * nss_mmu_ddr_info
 *	System DDR memory information required by the firmware MMU to set range guardian. ??what does "MMU to set range guardian" mean? And what is MMU?
 */
struct nss_mmu_ddr_info {
	uint32_t ddr_size;	/**< Total size of the DDR. */
	uint32_t start_address;	/**< System start address. */
};

/**
 * nss_n2h_msg
 *	Data for sending and receiving NSS-to-host messages.
 */
struct nss_n2h_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of an NSS-to-host message.
	 */
	union {
		struct nss_n2h_stats_sync stats_sync;
				/**< NSS-to-host synchronization statistics. */
		struct nss_n2h_rps rps_cfg;
				/**< RPS configuration. */
		struct nss_n2h_empty_pool_buf empty_pool_buf_cfg;
				/**< Empty pool buffer configuration. */
		struct nss_n2h_flush_payloads flush_payloads;
				/**< Flush payloads present in the NSS. */
		struct nss_n2h_mitigation mitigation_cfg;
				/**< Mitigation configuration. */
		struct nss_n2h_buf_pool buf_pool;
				/**< Pool buffer coniguration. */
		struct nss_n2h_water_mark wm;
				/**< Sets low and high watermarks. */
		struct nss_n2h_payload_info payload_info;
				/**< Gets the payload information. */
		struct nss_n2h_wifi_payloads wp;
				/**< Sets the number of Wi-Fi payloads. */
		struct nss_mmu_ddr_info mmu;
				/**< Use NSS-to-host for carrier, will change later.??good for PDF */
	} msg;			/**< Message payload. ??is this comment correct? I assumed it's the message payload because the first field is the message header */
};

/**
 * Callback function for receiving NSS-to-host messages.
 *
 * @datatypes
 * nss_n2h_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_n2h_msg_callback_t)(void *app_data, struct nss_n2h_msg *msg);

/**
 * nss_n2h_tx_msg
 *	Sends messages to the NSS-to-host package.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_n2h_msg
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 * @param[in]     nnm      Pointer to the ??.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_n2h_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_n2h_msg *nnm);

/**
 * nss_n2h_register_sysctl
 *	Registers system control for the NSS-to-host package.??
 *
 * @return
 * None.
 */
extern void nss_n2h_register_sysctl(void);

/**
 * nss_n2h_unregister_sysctl
 *	Degisters system control from?? the NSS-to-host package.??
 *
 * @return
 * None.
 *
 * @dependencies
 * The system control must have been previously registered.
 */
extern void nss_n2h_unregister_sysctl(void);

/**
 * nss_n2h_flush_payloads
 *	Sends flush payloads message to NSS
 *
 * @datatypes
 * nss_ctx_instance
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_n2h_flush_payloads(struct nss_ctx_instance *nss_ctx);

/**
 * nss_n2h_msg_init
 *	initializes messages from the host to the NSS.
 *
 * @datatypes
 * nss_n2h_msg \n
 * nss_n2h_msg_callback_t
 *
 * @param[in,out] nim       Pointer to the NSS interface message.
 * @param[in]     if_num    NSS interface number.
 * @param[in]     type      Type of message.
 * @param[in]     len       Size of the payload.
 * @param[in]     cb        Callback function for the message.
 * @param[in]     app_data  Pointer to the application context of the message.
 *
 * @return
 * None.
 */
extern void nss_n2h_msg_init(struct nss_n2h_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
			nss_n2h_msg_callback_t cb, void *app_data);

/**
 * @}
 */

#endif /* __NSS_N2H_H */



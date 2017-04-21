/*
 **************************************************************************
 * Copyright (c) 2014, 2016-2017, The Linux Foundation. All rights reserved.
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
 * @file nss_cmn.h
 *	NSS Common Message Structure and APIs
 */

#ifndef __NSS_CMN_H
#define __NSS_CMN_H

/**
 * @addtogroup nss_driver_api
 * @{
 */

/**
 * @struct nss_ctx_instance
	??Description here.
 */
struct nss_ctx_instance;

/*
 * The first 8 bits of an interfaces number is representing the core_id,
 * 0 means local core.
 */

#define NSS_CORE_ID_SHIFT 24		/**< ??Description here. */

/**
 * ??Description here.
 */
#define NSS_INTERFACE_NUM_APPEND_COREID(nss_ctx, interface) ((interface) | ((nss_ctx->id + 1) << NSS_CORE_ID_SHIFT))

/**
 * ??Description here.
 */
#define NSS_INTERFACE_NUM_GET(interface) ((interface) & 0xffffff)

/*
 * Common enumerations.
 */

/**
 * nss_tx_status_t
 *	Tx command failure results.
 */
typedef enum {
	NSS_TX_SUCCESS = 0,
	NSS_TX_FAILURE,
	NSS_TX_FAILURE_QUEUE,
	NSS_TX_FAILURE_NOT_READY,
	NSS_TX_FAILURE_TOO_LARGE,
	NSS_TX_FAILURE_TOO_SHORT,
	NSS_TX_FAILURE_NOT_SUPPORTED,
	NSS_TX_FAILURE_BAD_PARAM,
	NSS_TX_FAILURE_NOT_ENABLED,
} nss_tx_status_t;

/**
 * nss_state_t
 *	Initialization states.
 */
typedef enum {
	NSS_STATE_UNINITIALIZED = 0,
	NSS_STATE_INITIALIZED
} nss_state_t;

/**
 * nss_core_id_t
 *	NSS core IDs.
 */
typedef enum {
	NSS_CORE_0 = 0,
	NSS_CORE_1,
	NSS_CORE_MAX
} nss_core_id_t;

/**
 * nss_cb_register_status_t
 *	Callback registration states.
 */
typedef enum {
	NSS_CB_REGISTER_SUCCESS = 0,
	NSS_CB_REGISTER_FAILED,
} nss_cb_register_status_t;

/**
 * nss_cb_unregister_status_t
 *	Callback deregistration states.
 */
typedef enum {
	NSS_CB_UNREGISTER_SUCCESS = 0,
	NSS_CB_UNREGISTER_FAILED,
} nss_cb_unregister_status_t;

/**
 * nss_cmn_response
 *	Responses for a common message.
 */
enum nss_cmn_response {
	NSS_CMN_RESPONSE_ACK,
	NSS_CMN_RESPONSE_EVERSION,
	NSS_CMN_RESPONSE_EINTERFACE,
	NSS_CMN_RESPONSE_ELENGTH,
	NSS_CMN_RESPONSE_EMSG,
	NSS_CMM_RESPONSE_NOTIFY,
	NSS_CMN_RESPONSE_LAST
};

/**
 * Common response structure string ??need more info.
 */
extern int8_t *nss_cmn_response_str[NSS_CMN_RESPONSE_LAST];

/**
 * nss_cmn_msg
 *	Common message information.
 */
struct nss_cmn_msg {
	uint16_t version;	/**< Version ID for the main message format. */
	uint16_t len;		/**< Length of the message, excluding the header. */
	uint32_t interface;	/**< Primary key for all messages. */
	enum nss_cmn_response response;
				/**< Primary response. ??need more info */

	uint32_t type;	/**< Decentralized request number used to match response numbers. */
	uint32_t error;	/**< Decentralized specific error message (response == EMSG). */

	/**
	 * Padding used to start the callback from a 64-bit boundary.
	 * This can be reused.
	 */
	uint32_t reserved;

	nss_ptr_t cb;		/**< Contains the callback pointer. */
#ifndef __LP64__
	uint32_t padding1;	/**< Padding used to fit 64 bits. Do not reuse. */
#endif
	nss_ptr_t app_data;	/**< Contains the application data. */
#ifndef __LP64__
	uint32_t padding2;	/**< Padding used to fit 64 bits. Do not reuse. */
#endif
};

/**
 * nss_cmn_node_stats
 *	Common per-node statistics.
 */
struct nss_cmn_node_stats {
	uint32_t rx_packets;	/**< Number of packets received. */
	uint32_t rx_bytes;	/**< Number of bytes received. */
	uint32_t rx_dropped;	/**< Dropped packets received because the queue is full. */
	uint32_t tx_packets;	/**< Number of packets transmitted. */
	uint32_t tx_bytes;	/**< Number of bytes transmitted. */
};

/**
 * nss_cmn_get_msg_len
 *	Gets the message length of a host-to-NSS message.
 *
 * @datatypes
 * nss_cmn_get_msg_len
 *
 * @param[in] ncm  Pointer to the common message.
 *
 * @return
 * Message length ??
 */
static inline uint32_t nss_cmn_get_msg_len(struct nss_cmn_msg *ncm)
{
	return ncm->len + sizeof(struct nss_cmn_msg);
}

#ifdef __KERNEL__ /* only for kernel to use. */

/**
 * nss_cmn_msg_init
 *	Initializes the common area of a host-to-NSS message.
 *
 * @datatypes
 * nss_cmn_msg
 *
 * @param[in,out] ncm       Pointer to the common message.
 * @param[in]     if_num    NSS interface number.
 * @param[in]     type      Type of message.
 * @param[in]     len       Size of the payload.
 * @param[in]     cb        Pointer to the callback function.
 * @param[in]     app_data  Pointer to the application context for this message.
 *
 * @return
 * None.
 */
extern void nss_cmn_msg_init(struct nss_cmn_msg *ncm, uint16_t if_num, uint32_t type,  uint32_t len,
	void *cb, void *app_data);

/**
 * nss_cmn_get_interface_number
 *	Gets the interface number.
 *
 * @datatypes
 * nss_ctx_instance \n
 * net_device
 *
 * @param[in] nss_ctx  Pointer to the NSS context.
 * @param[in] dev      Pointer to the OS network device pointer.
 *
 * @return
 * Interface number.
 */
extern int32_t nss_cmn_get_interface_number(struct nss_ctx_instance *nss_ctx, struct net_device *dev);

/**
 * nss_cmn_get_interface_number_by_dev
 *	Gets the interface number of a device.
 *
 * @datatypes
 * net_device
 *
 * @param[in] dev  Pointer to the OS network device pointer.
 *
 * @return
 * Interface number, or 0 on failure.
 */
extern int32_t nss_cmn_get_interface_number_by_dev(struct net_device *dev);

/**
 * nss_cmn_interface_is_virtual
 *	Determines if the interface number is represented as a virtual interface.
 *
 * @param[in] nss_ctx        Pointer to the NSS context.
 * @param[in] interface_num  NSS interface number.
 *
 * @return
 * TRUE if the number is a virtual interface. ??or FALSE?
 */
extern bool nss_cmn_interface_is_virtual(void *nss_ctx, int32_t interface_num);

/**
 * nss_cmn_get_interface_dev
 *	Gets an interface device pointer.
 *
 * @datatypes
 * nss_ctx_instance
 *
 * @param[in] nss_ctx  Pointer to the NSS context.
 * @param[in] if_num     NSS interface number.
 *
 * @return
 * Interface device pointer.
 */
extern struct net_device *nss_cmn_get_interface_dev(struct nss_ctx_instance *nss_ctx, uint32_t if_num);

/**
 * nss_cmn_get_state
 *	Obtains the NSS state.
 *
 * @datatypes
 * nss_ctx_instance
 *
 * @param[in] nss_ctx  Pointer to the NSS context.
 *
 * @return
 * NSS state. ??
 */
extern nss_state_t nss_cmn_get_state(struct nss_ctx_instance *nss_ctx);

/**
 * Callback function for queue decongestion messages.
 *
 * @param[in] app_data  Pointer to the application context for this message.
 */
typedef void (*nss_cmn_queue_decongestion_callback_t)(void *app_data);

/**
 * nss_cmn_register_queue_decongestion
 *	Registers a queue for a decongestion event.
 *
 * The Callback function will be called with  the spinlock taken. ??what is meant here by "taken"?

 * @datatypes
 * nss_ctx_instance \n
 * nss_cmn_queue_decongestion_callback_t
 *
 * @param[in,out] nss_ctx         Pointer to the NSS context.
 * @param[in]     event_callback  Callback for the message.
 * @param[in]     app_data        Pointer to the application context to be returned in the
 *                                callback.
 *
 * @return
 * #NSS_CB_REGISTER_SUCCESS if registration is successful.
 * @par
 * Otherwise, #NSS_CB_REGISTER_FAILED.
 */
extern nss_cb_register_status_t nss_cmn_register_queue_decongestion(struct nss_ctx_instance *nss_ctx, nss_cmn_queue_decongestion_callback_t event_callback, void *app_data);

/**
 * nss_cmn_unregister_queue_decongestion
 *	Deregisters a queue from receiving a decongestion event.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_cmn_queue_decongestion_callback_t
 *
 * @param[in,out] nss_ctx         Pointer to the NSS context.
 * @param[in]     event_callback  Callback for the message.
 *
 * @return
 * #NSS_CB_REGISTER_SUCCESS if registration is successful.
 * @par
 * Otherwise, #NSS_CB_REGISTER_FAILED.
 *
 * @dependencies
 * The ??what? must have been previously registered.
 */
extern nss_cb_unregister_status_t nss_cmn_unregister_queue_decongestion(struct nss_ctx_instance *nss_ctx, nss_cmn_queue_decongestion_callback_t event_callback);

/**
 * nss_cmn_get_nss_enabled
 *	Checks whether the NSS mode is supported on the platform.
 *
 * @return
 * TRUE if NSS is supported. \n
 * Otherwise, FALSE.
 */
extern bool nss_cmn_get_nss_enabled(void);

#endif /* __KERNEL__ */

/**
 * @}
 */

#endif /* __NSS_CMN_MSG_H */

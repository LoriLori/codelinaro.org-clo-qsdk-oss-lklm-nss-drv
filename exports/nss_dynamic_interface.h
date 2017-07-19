/*
 **************************************************************************
 * Copyright (c) 2014-2017 The Linux Foundation. All rights reserved.
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
 * @file nss_dynamic_interface.h
 *	NSS Dynamic interface definitions.
 */

#ifndef __NSS_DYNAMIC_INTERFACE_H
#define __NSS_DYNAMIC_INTERFACE_H

/**
 * @addtogroup nss_dynamic_interface_subsystem
 * @{
 */

#define NSS_MAX_DYNAMIC_INTERFACES 64	/**< Maximum number of dynamic interfaces. */

/**
 * nss_dynamic_interface_type
 *	Dynamic interface types.
 */
enum nss_dynamic_interface_type {
	NSS_DYNAMIC_INTERFACE_TYPE_NONE,
	NSS_DYNAMIC_INTERFACE_TYPE_GRE_REDIR,
	NSS_DYNAMIC_INTERFACE_TYPE_CAPWAP,
	NSS_DYNAMIC_INTERFACE_TYPE_TUN6RD,
	NSS_DYNAMIC_INTERFACE_TYPE_802_3_REDIR,
	NSS_DYNAMIC_INTERFACE_TYPE_WIFI,
	NSS_DYNAMIC_INTERFACE_TYPE_VAP,
	NSS_DYNAMIC_INTERFACE_TYPE_RESERVED_1,
	NSS_DYNAMIC_INTERFACE_TYPE_RESERVED_2,
	NSS_DYNAMIC_INTERFACE_TYPE_VIRTIF_DEPRECATED,
	NSS_DYNAMIC_INTERFACE_TYPE_L2TPV2,
	NSS_DYNAMIC_INTERFACE_TYPE_PPTP,
	NSS_DYNAMIC_INTERFACE_TYPE_PORTID,
	NSS_DYNAMIC_INTERFACE_TYPE_DTLS,
	NSS_DYNAMIC_INTERFACE_TYPE_MAP_T,
	NSS_DYNAMIC_INTERFACE_TYPE_GRE_TUNNEL,
	NSS_DYNAMIC_INTERFACE_TYPE_BRIDGE,
	NSS_DYNAMIC_INTERFACE_TYPE_VLAN,
	NSS_DYNAMIC_INTERFACE_TYPE_GRE,
	NSS_DYNAMIC_INTERFACE_TYPE_WIFILI,
	NSS_DYNAMIC_INTERFACE_TYPE_MAX
};

typedef enum nss_dynamic_interface_type nss_dynamic_interface_assigned;

/**
 * nss_dynamic_interface_message_types
 *	Message types for dynamic interface requests.
 */
enum nss_dynamic_interface_message_types {
	NSS_DYNAMIC_INTERFACE_ALLOC_NODE,
	NSS_DYNAMIC_INTERFACE_DEALLOC_NODE,
	NSS_DYNAMIC_INTERFACE_MAX,
};

/**
 * nss_dynamic_interface_alloc_node_msg
 *	Message information for a dynamic interface allocation node.
 */
struct nss_dynamic_interface_alloc_node_msg {
	enum nss_dynamic_interface_type type;	/**< Type of dynamic interface. */

	/*
	 * Response.
	 */
	int if_num;				/**< Dynamic interface number. */
};

/**
 * nss_dynamic_interface_dealloc_node_msg
 *	Message information for dynamic interface deallocation node.
 */
struct nss_dynamic_interface_dealloc_node_msg {
	enum nss_dynamic_interface_type type;
			/**< Type of dynamic interface. */
	int if_num;	/**< Dynamic interface number. */
};

/**
 * nss_dynamic_interface_msg
 *	Data for sending and receiving dynamic interface messages.
 */
struct nss_dynamic_interface_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of a dynamic interface message.
	 */
	union {
		struct nss_dynamic_interface_alloc_node_msg alloc_node;
				/**< Allocates a dynamic node. */
		struct nss_dynamic_interface_dealloc_node_msg dealloc_node;
				/**< Deallocates a dynamic node. */
	} msg;			/**< Message payload. */
};

/**
 * nss_dynamic_interface_alloc_node
 *	Allocates a node for a dynamic interface.
 *
 * @datatypes
 * nss_dynamic_interface_type
 *
 * @param[in] type  Type of dynamic interface.
 *
 * @return
 * Number for the dynamic interface created.
 * @par
 * Otherwise, -1 for a failure.
 */
extern int nss_dynamic_interface_alloc_node(enum nss_dynamic_interface_type type);

/**
 * nss_dynamic_interface_dealloc_node
 *	Deallocates a node created for a dynamic interface on the NSS.
 *
 * @datatypes
 * nss_dynamic_interface_type
 *
 * @param[in] if_num  Dynamic interface number.
 * @param[in] type    Type of dynamic interface.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_dynamic_interface_dealloc_node(int if_num, enum nss_dynamic_interface_type type);

/**
 * nss_is_dynamic_interface
 *	Specifies whether the interface number belongs to the dynamic interface.
 *
 * @param[in] if_num  Dynamic interface number.
 *
 * @return
 * TRUE or FALSE
 */
extern bool nss_is_dynamic_interface(int if_num);

/**
 * nss_dynamic_interface_get_type
 *	Returns the type of dynamic interface.
 *
 * @param[in] nss_ctx  Pointer to the NSS context.
 * @param[in] if_num   Interface number of dynamic interface.
 *
 * @return
 * Type of dynamic interface per the dynamic interface number.
 */
extern enum nss_dynamic_interface_type nss_dynamic_interface_get_type(struct nss_ctx_instance *nss_ctx, int if_num);

/**
 * nss_dynamic_interface_tx
 *	Transmits an asynchronous message to the firmware.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_dynamic_interface_msg
 *
 * @param[in] nss_ctx  Pointer to the NSS context.
 * @param[in] msg      Pointer to the message data.
 *
 * @return
 * Status of the transmit operation.
 */
extern nss_tx_status_t nss_dynamic_interface_tx(struct nss_ctx_instance *nss_ctx, struct nss_dynamic_interface_msg *msg);

/**
 * Callback function for dynamic interface messages.
 *
 * @datatypes
 * nss_cmn_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_dynamic_interface_msg_callback_t)(void *app_data, struct nss_cmn_msg *msg);

/**
 * nss_dynamic_interface_msg_init
 *	Initializes a dynamic interface message.
 *
 * @datatypes
 * nss_dynamic_interface_msg
 *
 * @param[in] ndm       Pointer to the dynamic interface message.
 * @param[in] if_num    Dynamic interface number.
 * @param[in] type      Type of message.
 * @param[in] len       Size of the payload.
 * @param[in] cb        Pointer to the message callback.
 * @param[in] app_data  Pointer to the application context that is passed to the callback function.
 *
 * @return
 * None.
 */
void nss_dynamic_interface_msg_init(struct nss_dynamic_interface_msg *ndm, uint16_t if_num, uint32_t type, uint32_t len,
						void *cb, void *app_data);

/**
 * @}
 */

#endif /* __NSS_DYNAMIC_INTERFACE_H*/

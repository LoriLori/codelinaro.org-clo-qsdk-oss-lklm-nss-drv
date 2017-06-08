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
 * @file nss_dscp2pri.h
 *	NSS DSCP to Priority mapping interface definitions.
 */

#ifndef __NSS_DSCP2PRI_H
#define __NSS_DSCP2PRI_H

/**
 * @addtogroup nss_dscp2pri_subsystem
 * @{
 */

/**
 * nss_dscp2pri_priority
 *	Priority types mapped from DSCP values.
 */
enum nss_dscp2pri_priority {
	NSS_DSCP2PRI_PRIORITY_VO = 0,
	NSS_DSCP2PRI_PRIORITY_VI,
	NSS_DSCP2PRI_PRIORITY_BE,
	NSS_DSCP2PRI_PRIORITY_BK,
	NSS_DSCP2PRI_PRIORITY_MAX,
};

/**
 * nss_dscp2pri_action
 *	Action types mapped from DSCP values.
 */
enum nss_dscp2pri_action {
	NSS_DSCP2PRI_ACTION_NOT_ACCEL = 0,
	NSS_DSCP2PRI_ACTION_ACCEL,
	NSS_DSCP2PRI_ACTION_MAX,
};

/**
 * nss_dscp2pri_metadata_types
 *	Message types for dscp2pri requests.
 */
enum nss_dscp2pri_metadata_types {
	NSS_DSCP2PRI_METADATA_TYPE_CONFIGURE_MAPPING,
	NSS_DSCP2PRI_METADATA_TYPE_MAX,
};

/**
 * nss_dscp2pri_configure_mapping
 *	Send DSCP to Priority mapping message.
 */
struct nss_dscp2pri_configure_mapping {
	uint8_t dscp;		/**< Dscp value. */
	uint8_t priority;	/**< Priority value. */
	uint8_t opaque;		/**< Opaque value which is never used by NSS firmware. */
};

/**
 * nss_dscp2pri_msg
 *	Data for sending dscp2pri messages.
 */
struct nss_dscp2pri_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of a dscp2pri message.
	 */
	union {
		struct nss_dscp2pri_configure_mapping configure_mapping;
				/**< DSCP to Priority mapping configuration. */
	} msg;			/**< Message payload. */
};

/**
 * Callback function for receiving dscp2pri messages.
 *
 * @datatypes
 * nss_dscp2pri_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the dscp2pri message.
 */
typedef void (*nss_dscp2pri_msg_callback_t)(void *app_data, struct nss_dscp2pri_msg *msg);

/**
 * nss_dscp2pri_get_action
 *	Gets the action value of the DSCP.
 *
 * @param[in] dscp  Value of the DSCP field.
 *
 * @return
 * Action value of the DSCP field.
 */
enum nss_dscp2pri_action nss_dscp2pri_get_action(uint8_t dscp);

/**
 * nss_dscp2pri_register_sysctl
 *	Registers the dscp2pri sysctl entry to the sysctl tree.
 *
 * @return
 * None.
 */
void nss_dscp2pri_register_sysctl(void);

/**
 * nss_dscp2pri_unregister_sysctl
 *	Deregisters the dscp2pri sysctl entry from the sysctl tree.
 *
 * @return
 * None.
 *
 * @dependencies
 * The system control must have been previously registered.
 */
void nss_dscp2pri_unregister_sysctl(void);

/**
 * nss_dscp2pri_register_handler
 *	Registers the dscp2pri message handler.
 *
 * @return
 * None.
 */
void nss_dscp2pri_register_handler(void);

/**
 * @}
 */

#endif

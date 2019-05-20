/*
 **************************************************************************
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
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
 * @file nss_igs.h
 *	NSS ingress shaper interface definitions.
 */

#ifndef _NSS_IGS_H_
#define _NSS_IGS_H_

/**
 * @addtogroup NSS ingress shaper subsystem
 * @{
 */

/**
 * nss_igs_msg_types
 *	Message types for ingress shaper requests and responses.
 */
enum nss_igs_msg_types {
	NSS_IGS_MSG_SYNC_STATS = NSS_IF_MAX_MSG_TYPES + 1,
	NSS_IGS_MSG_MAX
};

/**
 * nss_igs_msg
 *	Data for sending and receiving ingress shaper messages.
 */
struct nss_igs_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of a ingress shaper message.
	 */
	union {
		union nss_if_msgs if_msg;
				/**< NSS interface base message. */
	} msg;			/**< Message payload. */
};

/**
 * Callback function for receiving ingress shaper messages.
 *
 * @datatypes
 * nss_cmn_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_igs_msg_callback_t)(void *app_data, struct nss_cmn_msg *msg);

/**
 * nss_igs_get_context
 *	Gets the ingress shaper context.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_igs_get_context(void);

/**
 * nss_igs_register_if
 *	Registers a ingress shaper interface with the NSS for sending and receiving messages.
 *
 * @datatypes
 * nss_igs_msg_callback_t \n
 * net_device
 *
 * @param[in] if_num          NSS interface number.
 * @param[in] type            NSS interface type.
 * @param[in] msg_callback    Callback for the ingress shaper message.
 * @param[in] netdev          Pointer to the associated network device.
 * @param[in] features        Data socket buffer types supported by this interface.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_igs_register_if(uint32_t if_num, uint32_t type,
		nss_igs_msg_callback_t msg_callback, struct net_device *netdev, uint32_t features);

/**
 * nss_igs_unregister_if
 *	Deregisters a ingress shaper interface from the NSS.
 *
 * @param[in] if_num  NSS interface number.
 *
 * @return
 * None.
 */
extern void nss_igs_unregister_if(uint32_t if_num);

/**
 * nss_igs_verify_if_num
 *	Verify whether interface is an ingress shaper interface or not.
 *
 * @param[in] if_num  NSS interface number.
 *
 * @return
 * True if interface is an ingress shaper interface.
 */
extern bool nss_igs_verify_if_num(uint32_t if_num);

/**
 * @}
 */
#endif

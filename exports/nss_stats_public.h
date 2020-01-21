/*
 **************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
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
 * @file nss_stats_public.h
 *	NSS statistics Structure and APIs
 */

#ifndef __NSS_STATS_PUBLIC_H
#define __NSS_STATS_PUBLIC_H

/**
 * @addtogroup nss_stats_public_subsystem
 * @{
 */

/**
 * Maximum string length.
 *
 * This should be equal to maximum string size of any statistics
 * inclusive of statistics value.
 */
#define NSS_STATS_MAX_STR_LENGTH 96

/**
 * nss_stats_node
 *	Node statistics.
 */
enum nss_stats_node {
	NSS_STATS_NODE_RX_PKTS,			/**< Accelerated node Rx packets. */
	NSS_STATS_NODE_RX_BYTES,		/**< Accelerated node Rx bytes. */
	NSS_STATS_NODE_TX_PKTS,			/**< Accelerated node Tx packets. */
	NSS_STATS_NODE_TX_BYTES,		/**< Accelerated node Tx bytes. */
	NSS_STATS_NODE_RX_QUEUE_0_DROPPED,	/**< Accelerated node Rx Queue 0 dropped. */
	NSS_STATS_NODE_RX_QUEUE_1_DROPPED,	/**< Accelerated node Rx Queue 1 dropped. */
	NSS_STATS_NODE_RX_QUEUE_2_DROPPED,	/**< Accelerated node Rx Queue 2 dropped. */
	NSS_STATS_NODE_RX_QUEUE_3_DROPPED,	/**< Accelerated node Rx Queue 3 dropped. */
	NSS_STATS_NODE_MAX,			/**< Maximum message type. */
};

/**
 * nss_stats_types
 *	List of statistics categories.
 */
enum nss_stats_types {
	NSS_STATS_TYPE_COMMON,			/**< Common pnode statistics. */
	NSS_STATS_TYPE_DROP,			/**< Packet drop statistics. */
	NSS_STATS_TYPE_ERROR,			/**< Hardware or software errors different from drop or exception statistics. */
	NSS_STATS_TYPE_EXCEPTION,		/**< Packet exception (to host) statistics. */
	NSS_STATS_TYPE_SPECIAL,			/**< Statistics that do not fall into the above types. */
	NSS_STATS_TYPE_MAX			/**< Maximum message type. */
};

/**
 * nss_stats_notifier_action
 *	Statistics notification types.
 */
enum nss_stats_notifier_action {
	NSS_STATS_EVENT_NOTIFY,
	NSS_STATS_EVENT_MAX
};

/**
 * @}
 */

#endif /* __NSS_STATS_PUBLIC_H */

/*
 **************************************************************************
 * Copyright (c) 2013-2017, The Linux Foundation. All rights reserved.
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
 * na_core.h
 *	NSS driver core header file.
 */

#ifndef __NSS_CORE_H
#define __NSS_CORE_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>

#include <nss_api_if.h>
#include "nss_phys_if.h"
#include "nss_hlos_if.h"
#include "nss_oam.h"
#include "nss_data_plane.h"

/*
 * XXX:can't add this to api_if.h till the deprecated
 * API(s) are present. Once, thats removed we will move it
 * to this file
 */
#include "nss_ipsec.h"
#include "nss_crypto.h"

/*
 * NSS debug macros
 */
#define nss_info_always(s, ...) pr_alert(s, ##__VA_ARGS__)

#if (NSS_DEBUG_LEVEL < 1)
#define nss_assert(fmt, args...)
#else
#define nss_assert(c) if (!(c)) { BUG_ON(!(c)); }
#endif

#if defined(CONFIG_DYNAMIC_DEBUG)
/*
 * Compile messages for dynamic enable/disable
 */
#define nss_warning(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define nss_info(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define nss_trace(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else

/*
 * Statically compile messages at different levels
 */
#if (NSS_DEBUG_LEVEL < 2)
#define nss_warning(s, ...)
#else
#define nss_warning(s, ...) pr_warn("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (NSS_DEBUG_LEVEL < 3)
#define nss_info(s, ...)
#else
#define nss_info(s, ...) pr_notice("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (NSS_DEBUG_LEVEL < 4)
#define nss_trace(s, ...)
#else
#define nss_trace(s, ...) pr_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif
#endif

#if (NSS_PKT_STATS_ENABLED == 1)
#define NSS_PKT_STATS_INCREMENT(nss_ctx, x) nss_pkt_stats_increment((nss_ctx), (x))
#define NSS_PKT_STATS_DECREMENT(nss_ctx, x) nss_pkt_stats_decrement((nss_ctx), (x))
#define NSS_PKT_STATS_READ(x) nss_pkt_stats_read(x)
#else
#define NSS_PKT_STATS_INCREMENT(nss_ctx, x)
#define NSS_PKT_STATS_DECREMENT(nss_ctx, x)
#define NSS_PKT_STATS_READ(x) (0)
#endif

/*
 * NSS max values supported
 */
#define NSS_MAX_CORES 2
#define NSS_MAX_DEVICE_INTERFACES (NSS_MAX_PHYSICAL_INTERFACES + NSS_MAX_VIRTUAL_INTERFACES + NSS_MAX_TUNNEL_INTERFACES + NSS_MAX_DYNAMIC_INTERFACES)
#define NSS_MAX_NET_INTERFACES (NSS_MAX_DEVICE_INTERFACES + NSS_MAX_SPECIAL_INTERFACES)

#define NSS_DEVICE_IF_START NSS_PHYSICAL_IF_START

#define NSS_IS_IF_TYPE(type, if_num) ((if_num >= NSS_##type##_IF_START) && (if_num < (NSS_##type##_IF_START + NSS_MAX_##type##_INTERFACES)))

/*
 * Default payload size for NSS buffers
 */
#define NSS_NBUF_PAYLOAD_SIZE NSS_EMPTY_BUFFER_SIZE
#define NSS_NBUF_PAD_EXTRA 256
#define NSS_NBUF_ETH_EXTRA 192

/*
 * N2H/H2N Queue IDs
 */
#define NSS_IF_EMPTY_BUFFER_QUEUE 0
#define NSS_IF_DATA_QUEUE_0 1
#define NSS_IF_DATA_QUEUE_1 2
#define NSS_IF_DATA_QUEUE_2 3
#define NSS_IF_DATA_QUEUE_3 4
#define NSS_IF_CMD_QUEUE 1

/*
 * NSS Interrupt Causes
 */
#define NSS_INTR_CAUSE_INVALID 0
#define NSS_INTR_CAUSE_QUEUE 1
#define NSS_INTR_CAUSE_NON_QUEUE 2
#define NSS_INTR_CAUSE_EMERGENCY 3

/*
 * NSS Core Status
 */
#define NSS_CORE_STATUS_SUCCESS 0
#define NSS_CORE_STATUS_FAILURE 1
#define NSS_CORE_STATUS_FAILURE_QUEUE 2

/*
 * NSS context magic
 */
#define NSS_CTX_MAGIC 0xDEDEDEDE

/*
 * Number of n2h descriptor rings
 */
#define NSS_N2H_DESC_RING_NUM 15
#define NSS_H2N_DESC_RING_NUM 16

/*
 * NSS maximum data queue per core
 */
#define NSS_MAX_DATA_QUEUE 4

/*
 * NSS maximum IRQ per interrupt instance/core
 */
#if defined(NSS_HAL_IPQ807x_SUPPORT)
#define NSS_MAX_IRQ_PER_INSTANCE 4
#define NSS_MAX_IRQ_PER_CORE 7
#else
#define NSS_MAX_IRQ_PER_INSTANCE 1
#define NSS_MAX_IRQ_PER_CORE 2
#endif

/*
 * NSS maximum clients
 */
#define NSS_MAX_CLIENTS 12

/*
 * Interrupt cause processing weights
 */
#define NSS_EMPTY_BUFFER_SOS_PROCESSING_WEIGHT 64
#define NSS_DATA_COMMAND_BUFFER_PROCESSING_WEIGHT 64
#define NSS_EMPTY_BUFFER_RETURN_PROCESSING_WEIGHT 64
#define NSS_TX_UNBLOCKED_PROCESSING_WEIGHT 1

/*
 * Statistics struct
 *
 * INFO: These numbers are based on previous generation chip
 *	These may change in future
 */
#define NSS_PPPOE_NUM_SESSION_PER_INTERFACE 4
					/* Number of maximum simultaneous PPPoE sessions per physical interface */
/*
 * NSS Frequency Defines and Values
 *
 * INFO: The LOW and MAX value together describe the "performance" band that we should operate the frequency at.
 *
 */
#define NSS_FREQ_110		110000000	/* Frequency in hz */
#define NSS_FREQ_110_MIN	0x03000		/* Instructions Per ms Min */
#define NSS_FREQ_110_MAX	0x07000		/* Instructions Per ms Max */

#define NSS_FREQ_275		275000000	/* Frequency in hz */
#define NSS_FREQ_275_MIN	0x03000		/* Instructions Per ms Min */
#define NSS_FREQ_275_MAX	0x07000		/* Instructions Per ms Max */

#define NSS_FREQ_550		550000000	/* Frequency in hz */
#define NSS_FREQ_550_MIN	0x07000		/* Instructions Per ms Min */
#define NSS_FREQ_550_MAX	0x08000		/* Instructions Per ms Max */

#define NSS_FREQ_600		600000000	/* Frequency in hz */
#define NSS_FREQ_600_MIN	0x07000		/* Instructions Per ms Min */
#define NSS_FREQ_600_MAX	0x08000		/* Instructions Per ms Max */

#define NSS_FREQ_733		733000000	/* Frequency in hz */
#define NSS_FREQ_733_MIN	0x07000		/* Instructions Per ms Min */
#define NSS_FREQ_733_MAX	0x25000		/* Instructions Per ms Max */

#define NSS_FREQ_800		800000000	/* Frequency in hz */
#define NSS_FREQ_800_MIN	0x07000		/* Instructions Per ms Min */
#define NSS_FREQ_800_MAX	0x25000		/* Instructions Per ms Max */

#if (NSS_DT_SUPPORT == 1)
#define NSSTCM_FREQ		400000000	/* NSS TCM Frequency in Hz */

/* NSS Clock names */
#define NSS_CORE_CLK		"nss-core-clk"
#define NSS_TCM_SRC_CLK		"nss-tcm-src"
#define NSS_TCM_CLK		"nss-tcm-clk"
#define NSS_FABRIC0_CLK		"nss-fab0-clk"
#define NSS_FABRIC1_CLK		"nss-fab1-clk"

/* NSS Fabric speeds */
#define NSS_FABRIC0_TURBO	533000000
#define NSS_FABRIC1_TURBO	266500000
#define NSS_FABRIC0_NOMINAL	400000000
#define NSS_FABRIC1_NOMINAL	200000000
#define NSS_FABRIC0_IDLE	133333000
#define NSS_FABRIC1_IDLE	133333000
#endif

/*
 * Gives us important data from NSS platform data
 */
extern struct nss_top_instance nss_top_main;

/*
 * IPV4 node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_ipv4 {
	NSS_STATS_IPV4_ACCELERATED_RX_PKTS = 0,
					/* Accelerated IPv4 RX packets */
	NSS_STATS_IPV4_ACCELERATED_RX_BYTES,
					/* Accelerated IPv4 RX bytes */
	NSS_STATS_IPV4_ACCELERATED_TX_PKTS,
					/* Accelerated IPv4 TX packets */
	NSS_STATS_IPV4_ACCELERATED_TX_BYTES,
					/* Accelerated IPv4 TX bytes */
	NSS_STATS_IPV4_CONNECTION_CREATE_REQUESTS,
					/* Number of IPv4 connection create requests */
	NSS_STATS_IPV4_CONNECTION_CREATE_COLLISIONS,
					/* Number of IPv4 connection create requests that collided with existing entries */
	NSS_STATS_IPV4_CONNECTION_CREATE_INVALID_INTERFACE,
					/* Number of IPv4 connection create requests that had invalid interface */
	NSS_STATS_IPV4_CONNECTION_DESTROY_REQUESTS,
					/* Number of IPv4 connection destroy requests */
	NSS_STATS_IPV4_CONNECTION_DESTROY_MISSES,
					/* Number of IPv4 connection destroy requests that missed the cache */
	NSS_STATS_IPV4_CONNECTION_HASH_HITS,
					/* Number of IPv4 connection hash hits */
	NSS_STATS_IPV4_CONNECTION_HASH_REORDERS,
					/* Number of IPv4 connection hash reorders */
	NSS_STATS_IPV4_CONNECTION_FLUSHES,
					/* Number of IPv4 connection flushes */
	NSS_STATS_IPV4_CONNECTION_EVICTIONS,
					/* Number of IPv4 connection evictions */
	NSS_STATS_IPV4_FRAGMENTATIONS,
					/* Number of successful IPv4 fragmentations performed */
	NSS_STATS_IPV4_MC_CONNECTION_CREATE_REQUESTS,
					/* Number of successful IPv4 Multicast create requests */
	NSS_STATS_IPV4_MC_CONNECTION_UPDATE_REQUESTS,
					/* Number of successful IPv4 Multicast update requests */
	NSS_STATS_IPV4_MC_CONNECTION_CREATE_INVALID_INTERFACE,
					/* Number of IPv4 Multicast connection create requests that had invalid interface */
	NSS_STATS_IPV4_MC_CONNECTION_DESTROY_REQUESTS,
					/* Number of IPv4 Multicast connection destroy requests */
	NSS_STATS_IPV4_MC_CONNECTION_DESTROY_MISSES,
					/* Number of IPv4 Multicast connection destroy requests that missed the cache */
	NSS_STATS_IPV4_MC_CONNECTION_FLUSHES,
					/* Number of IPv4 Multicast connection flushes */
	NSS_STATS_IPV4_MAX,
};

/*
 * IPV4 reasm node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_ipv4_reasm {
	NSS_STATS_IPV4_REASM_EVICTIONS = 0,
					/* Number of evicted fragment queues due to set memory threshold */
	NSS_STATS_IPV4_REASM_ALLOC_FAILS,
					/* Number of fragment queue allocation failures */
	NSS_STATS_IPV4_REASM_TIMEOUTS,
					/* Number of expired fragment queues */
	NSS_STATS_IPV4_REASM_MAX,
};

/*
 * IPV6 node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_ipv6 {
	NSS_STATS_IPV6_ACCELERATED_RX_PKTS = 0,
					/* Accelerated IPv6 RX packets */
	NSS_STATS_IPV6_ACCELERATED_RX_BYTES,
					/* Accelerated IPv6 RX bytes */
	NSS_STATS_IPV6_ACCELERATED_TX_PKTS,
					/* Accelerated IPv6 TX packets */
	NSS_STATS_IPV6_ACCELERATED_TX_BYTES,
					/* Accelerated IPv6 TX bytes */
	NSS_STATS_IPV6_CONNECTION_CREATE_REQUESTS,
					/* Number of IPv6 connection create requests */
	NSS_STATS_IPV6_CONNECTION_CREATE_COLLISIONS,
					/* Number of IPv6 connection create requests that collided with existing entries */
	NSS_STATS_IPV6_CONNECTION_CREATE_INVALID_INTERFACE,
					/* Number of IPv6 connection create requests that had invalid interface */
	NSS_STATS_IPV6_CONNECTION_DESTROY_REQUESTS,
					/* Number of IPv6 connection destroy requests */
	NSS_STATS_IPV6_CONNECTION_DESTROY_MISSES,
					/* Number of IPv6 connection destroy requests that missed the cache */
	NSS_STATS_IPV6_CONNECTION_HASH_HITS,
					/* Number of IPv6 connection hash hits */
	NSS_STATS_IPV6_CONNECTION_HASH_REORDERS,
					/* Number of IPv6 connection hash reorders */
	NSS_STATS_IPV6_CONNECTION_FLUSHES,
					/* Number of IPv6 connection flushes */
	NSS_STATS_IPV6_CONNECTION_EVICTIONS,
					/* Number of IPv6 connection evictions */
	NSS_STATS_IPV6_FRAGMENTATIONS,
					/* Number of successful IPv6 fragmentations performed */
	NSS_STATS_IPV6_FRAG_FAILS,
					/* Number of IPv6 fragmentation fails */
	NSS_STATS_IPV6_MC_CONNECTION_CREATE_REQUESTS,
					/* Number of successful IPv6 Multicast create requests */
	NSS_STATS_IPV6_MC_CONNECTION_UPDATE_REQUESTS,
					/* Number of successful IPv6 Multicast update requests */
	NSS_STATS_IPV6_MC_CONNECTION_CREATE_INVALID_INTERFACE,
					/* Number of IPv6 Multicast connection create requests that had invalid interface */
	NSS_STATS_IPV6_MC_CONNECTION_DESTROY_REQUESTS,
					/* Number of IPv6 Multicast connection destroy requests */
	NSS_STATS_IPV6_MC_CONNECTION_DESTROY_MISSES,
					/* Number of IPv6 Multicast connection destroy requests that missed the cache */
	NSS_STATS_IPV6_MC_CONNECTION_FLUSHES,
					/* Number of IPv6 Multicast connection flushes */
	NSS_STATS_IPV6_MAX,
};

/*
 * IPv6 reasm node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_ipv6_reasm {
	NSS_STATS_IPV6_REASM_ALLOC_FAILS = 0,
					/* Number of fragment queue allocation failures */
	NSS_STATS_IPV6_REASM_TIMEOUTS,
					/* Number of expired fragment queues */
	NSS_STATS_IPV6_REASM_DISCARDS,
					/* Number of fragment queues discarded due to malformed fragments*/
	NSS_STATS_IPV6_REASM_MAX,
};

/*
 * HLOS driver statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_drv {
	NSS_STATS_DRV_NBUF_ALLOC_FAILS = 0,	/* NBUF allocation errors */
	NSS_STATS_DRV_TX_QUEUE_FULL_0,		/* Tx queue full for Core 0*/
	NSS_STATS_DRV_TX_QUEUE_FULL_1,		/* Tx queue full for Core 1*/
	NSS_STATS_DRV_TX_EMPTY,			/* H2N Empty buffers */
	NSS_STATS_DRV_TX_PACKET,		/* H2N Data packets */
	NSS_STATS_DRV_TX_CMD_REQ,		/* H2N Control packets */
	NSS_STATS_DRV_TX_CRYPTO_REQ,		/* H2N Crypto requests */
	NSS_STATS_DRV_TX_BUFFER_REUSE,		/* H2N Reuse buffer count */
	NSS_STATS_DRV_RX_EMPTY,			/* N2H Empty buffers */
	NSS_STATS_DRV_RX_PACKET,		/* N2H Data packets */
	NSS_STATS_DRV_RX_CMD_RESP,		/* N2H Command responses */
	NSS_STATS_DRV_RX_STATUS,		/* N2H Status packets */
	NSS_STATS_DRV_RX_CRYPTO_RESP,		/* N2H Crypto responses */
	NSS_STATS_DRV_RX_VIRTUAL,		/* N2H Virtual packets */
	NSS_STATS_DRV_TX_SIMPLE,		/* H2N Simple SKB Packets */
	NSS_STATS_DRV_TX_NR_FRAGS,		/* H2N NR Frags SKB Packets */
	NSS_STATS_DRV_TX_FRAGLIST,		/* H2N Fraglist SKB Packets */
	NSS_STATS_DRV_RX_SIMPLE,		/* N2H Simple SKB Packets */
	NSS_STATS_DRV_RX_NR_FRAGS,		/* N2H NR Frags SKB Packets */
	NSS_STATS_DRV_RX_SKB_FRAGLIST,		/* N2H Fraglist SKB Packets */
	NSS_STATS_DRV_RX_BAD_DESCRIPTOR,	/* N2H Bad descriptor reads */
	NSS_STATS_DRV_NSS_SKB_COUNT,		/* NSS SKB Pool Count */
	NSS_STATS_DRV_CHAIN_SEG_PROCESSED,	/* N2H SKB Chain Processed Count */
	NSS_STATS_DRV_FRAG_SEG_PROCESSED,	/* N2H Frag Processed Count */
	NSS_STATS_DRV_MAX,
};

/*
 * PPPoE statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_pppoe {
	NSS_STATS_PPPOE_SESSION_CREATE_REQUESTS = 0,
					/* Number of PPPoE session create requests */
	NSS_STATS_PPPOE_SESSION_CREATE_FAILURES,
					/* Number of PPPoE session create failures */
	NSS_STATS_PPPOE_SESSION_DESTROY_REQUESTS,
					/* Number of PPPoE session destroy requests */
	NSS_STATS_PPPOE_SESSION_DESTROY_MISSES,
					/* Number of PPPoE session destroy requests that missed the cache */
	NSS_STATS_PPPOE_MAX,
};

/*
 * GMAC node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_gmac {
	NSS_STATS_GMAC_TOTAL_TICKS = 0,
					/* Total clock ticks spend inside the GMAC */
	NSS_STATS_GMAC_WORST_CASE_TICKS,
					/* Worst case iteration of the GMAC in ticks */
	NSS_STATS_GMAC_ITERATIONS,	/* Number of iterations around the GMAC */
	NSS_STATS_GMAC_MAX,
};

/*
 * ETH_RX node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_eth_rx {
	NSS_STATS_ETH_RX_TOTAL_TICKS = 0,
					/* Total clock ticks spend inside the eth_rx package */
	NSS_STATS_ETH_RX_WORST_CASE_TICKS,
					/* Worst case iteration of the eth_rx in ticks */
	NSS_STATS_ETH_RX_ITERATIONS,	/* Number of iterations around the eth_rx */
	NSS_STATS_ETH_RX_MAX,
};

/*
 * Node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_node {
	NSS_STATS_NODE_RX_PKTS,
					/* Accelerated node RX packets */
	NSS_STATS_NODE_RX_BYTES,
					/* Accelerated node RX bytes */
	NSS_STATS_NODE_RX_DROPPED,
					/* Accelerated node RX dropped */
	NSS_STATS_NODE_TX_PKTS,
					/* Accelerated node TX packets */
	NSS_STATS_NODE_TX_BYTES,
					/* Accelerated node TX bytes */
	NSS_STATS_NODE_MAX,
};

/*
 * N2H node statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_n2h {
	NSS_STATS_N2H_QUEUE_DROPPED = NSS_STATS_NODE_MAX,
					/* Number of packets dropped because the exception queue is too full */
	NSS_STATS_N2H_TOTAL_TICKS,	/* Total clock ticks spend inside the N2H */
	NSS_STATS_N2H_WORST_CASE_TICKS,	/* Worst case iteration of the exception path in ticks */
	NSS_STATS_N2H_ITERATIONS,	/* Number of iterations around the N2H */

	NSS_STATS_N2H_PBUF_OCM_ALLOC_FAILS,	/* Number of pbuf ocm allocations that have failed */
	NSS_STATS_N2H_PBUF_OCM_FREE_COUNT,	/* Number of pbuf ocm free count */
	NSS_STATS_N2H_PBUF_OCM_TOTAL_COUNT,	/* Number of pbuf ocm total count */

	NSS_STATS_N2H_PBUF_DEFAULT_ALLOC_FAILS,	/* Number of pbuf default allocations that have failed */
	NSS_STATS_N2H_PBUF_DEFAULT_FREE_COUNT,	/* Number of pbuf default free count */
	NSS_STATS_N2H_PBUF_DEFAULT_TOTAL_COUNT,	/* Number of pbuf default total count */

	NSS_STATS_N2H_PAYLOAD_ALLOC_FAILS,	/* Number of pbuf allocations that have failed because there were no free payloads */
	NSS_STATS_N2H_PAYLOAD_FREE_COUNT,	/* Number of free payloads that exist */

	NSS_STATS_N2H_H2N_CONTROL_PACKETS,	/* Control packets received from HLOS */
	NSS_STATS_N2H_H2N_CONTROL_BYTES,	/* Control bytes received from HLOS */
	NSS_STATS_N2H_N2H_CONTROL_PACKETS,	/* Control packets sent to HLOS */
	NSS_STATS_N2H_N2H_CONTROL_BYTES,	/* Control bytes sent to HLOS */

	NSS_STATS_N2H_H2N_DATA_PACKETS,		/* Data packets received from HLOS */
	NSS_STATS_N2H_H2N_DATA_BYTES,		/* Data bytes received from HLOS */
	NSS_STATS_N2H_N2H_DATA_PACKETS,		/* Data packets sent to HLOS */
	NSS_STATS_N2H_N2H_DATA_BYTES,		/* Data bytes sent to HLOS */
	NSS_STATS_N2H_N2H_TOT_PAYLOADS,		/* No. of payloads in NSS */
	NSS_STATS_N2H_N2H_INTERFACE_INVALID,	/* No. of bad interface access */

	NSS_STATS_N2H_MAX,
};

/*
 * LSO_RX driver statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_lso_rx {
	NSS_STATS_LSO_RX_TX_DROPPED,		/* Number of packets dropped cause transmit queue is full */
	NSS_STATS_LSO_RX_DROPPED,		/* Number of packets dropped because of node internal errors */
	NSS_STATS_LSO_RX_PBUF_ALLOC_FAIL,	/* Number of pbuf alloc failures */
	NSS_STATS_LSO_RX_PBUF_REFERENCE_FAIL,	/* Number of pbuf reference failures */
	NSS_STATS_LSO_RX_MAX,
};

/*
 * wifi statistics
 */
enum nss_stats_wifi {
	NSS_STATS_WIFI_RX_PKTS,				/* Number of packets enqueud to wifi */
	NSS_STATS_WIFI_RX_DROPPED,			/* Number of packet dropped during enqueue to wifi */
	NSS_STATS_WIFI_TX_PKTS,				/* Number of packets transmited out to wifi */
	NSS_STATS_WIFI_TX_DROPPED,			/* Number of packets dropped during transmission */
	NSS_STATS_WIFI_TX_COMPLETED,			/* Number of packets for which transmission completion received */
	NSS_STATS_WIFI_MGMT_RCV_CNT,			/* Number of management packets received from host for transmission */
	NSS_STATS_WIFI_MGMT_TX_PKTS,			/* Number of management packets transmitted over wifi */
	NSS_STATS_WIFI_MGMT_TX_DROPPED,			/* Number of management packets dropped because of transmission failure */
	NSS_STATS_WIFI_MGMT_TX_COMPLETIONS,		/* Number of management packets for which tx completions are received */
	NSS_STATS_WIFI_TX_INV_PEER_ENQUEUE_CNT,		/* Number of packets for which tx enqueue failed because of invalid peer */
	NSS_STATS_WIFI_RX_INV_PEER_RCV_CNT,		/* Number of packets received from wifi with invalid peer id */
	NSS_STATS_WIFI_RX_PN_CHECK_FAILED,		/* Number of rx packets which failed packet number check */
	NSS_STATS_WIFI_RX_DELIVERED,			/* Number of rx packets that NSS wifi offload path could successfully process */
	NSS_STATS_WIFI_RX_BYTES_DELIVERED,		/* Number of rx bytes that NSS wifi offload path could successfully process */
	NSS_STATS_WIFI_TX_BYTES_COMPLETED,		/* Number of bytes for which transmission completion received */
	NSS_STATS_WIFI_RX_DELIVER_UNALIGNED_DROP_CNT,	/* Number of rx packets that dropped beacause of alignment mismatch*/
	NSS_STATS_WIFI_TIDQ_ENQUEUE_CNT,		/* Number of packets enqueued to  TIDQ */
	NSS_STATS_WIFI_TIDQ_DEQUEUE_CNT = NSS_STATS_WIFI_TIDQ_ENQUEUE_CNT + 8,		/* Number of packets dequeued from  TIDQ */
	NSS_STATS_WIFI_TIDQ_ENQUEUE_FAIL_CNT = NSS_STATS_WIFI_TIDQ_DEQUEUE_CNT + 8,	/* Enqueue fail count */
	NSS_STATS_WIFI_TIDQ_TTL_EXPIRE_CNT = NSS_STATS_WIFI_TIDQ_ENQUEUE_FAIL_CNT + 8,	/* Number of packets expired from  TIDQ */
	NSS_STATS_WIFI_TIDQ_DEQUEUE_REQ_CNT = NSS_STATS_WIFI_TIDQ_TTL_EXPIRE_CNT + 8,	/* Dequeue reuest count from wifi fw */
	NSS_STATS_WIFI_TOTAL_TIDQ_DEPTH = NSS_STATS_WIFI_TIDQ_DEQUEUE_REQ_CNT + 8,	/* Tidq depth */
	NSS_STATS_WIFI_RX_HTT_FETCH_CNT,	/* Total number of HTT Fetch Messages received from wifi fw */
	NSS_STATS_WIFI_TOTAL_TIDQ_BYPASS_CNT,	/* Total number of packets which have bypassed tidq and sent to wifi fw */
	NSS_STATS_WIFI_GLOBAL_Q_FULL_CNT,	/* Total number of packets dropped due to global queue full condition */
	NSS_STATS_WIFI_TIDQ_FULL_CNT,		/* Total number of packets dropped due to TID queue full condition */
	NSS_STATS_WIFI_MAX,
};

/*
 * wifili txrx statistics
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_txrx {
	NSS_STATS_WIFILI_RX_MSDU_ERROR,			/* Number of rx packets received from ring with msdu error */
	NSS_STATS_WIFILI_RX_INV_PEER_RCV,		/* Number of rx packets with invalid peer id */
	NSS_STATS_WIFILI_RX_WDS_SRCPORT_EXCEPTION,	/* Number of rx packets exceptioned to host because of src port learn fail */
	NSS_STATS_WIFILI_RX_WDS_SRCPORT_EXCEPTION_FAIL,	/* Number of rx src port learn fail packets failed to get enqueued to host */
	NSS_STATS_WIFILI_RX_DELIVERD,			/* Number of packets wifili has given to next node */
	NSS_STATS_WIFILI_RX_DELIVER_DROPPED,		/* Number of packets which wifili failed to enqueue to next node */
	NSS_STATS_WIFILI_RX_INTRA_BSS_UCAST,		/* Number of packets which wifili send for intra bss ucast packet */
	NSS_STATS_WIFILI_RX_INTRA_BSS_UCAST_FAIL,	/* Number of packets which wifili send for intra bss ucast packet failed */
	NSS_STATS_WIFILI_RX_INTRA_BSS_MCAST,		/* Number of packets which wifili send for intra bss mcast packet */
	NSS_STATS_WIFILI_RX_INTRA_BSS_MCAST_FAIL,	/* Number of packets which wifili send for intra bss mcast packet failed */
	NSS_STATS_WIFILI_RX_SG_RCV_SEND,		/* Number of packets sg send */
	NSS_STATS_WIFILI_RX_SG_RCV_FAIL,		/* Number of packets sg received failure*/
	NSS_STATS_WIFILI_TX_ENQUEUE,			/* Number of packets that got enqueued to wifili */
	NSS_STATS_WIFILI_TX_ENQUEUE_DROP,		/* Number of packets that dropped during enqueue to wifili */
	NSS_STATS_WIFILI_TX_DEQUEUE,			/* Number of packets that are dequeued by wifili */
	NSS_STATS_WIFILI_TX_HW_ENQUEUE_FAIL,		/* Number of rx packets that NSS wifi offload path could successfully process */
	NSS_STATS_WIFILI_TX_SENT_COUNT,			/* Number of Tx packets sent to hw */
	NSS_STATS_WIFILI_TXRX_MAX,			/* Number of max txrx stats*/
};

/*
 * wifili tcl stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_tcl {
	NSS_STATS_WIFILI_TCL_NO_HW_DESC,		/* Number of tcl hw desc*/
	NSS_STATS_WIFILI_TCL_RING_FULL,			/* Number of times tcl ring full*/
	NSS_STATS_WIFILI_TCL_RING_SENT,			/* Number of times tcl desc sent*/
	NSS_STATS_WIFILI_TCL_MAX,			/* Number of max tcl stats*/
};

/*
 * wifili tx comp stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *  	stats string array in nss_stats.c
 */
enum nss_stats_wifili_tx_comp {
	NSS_STATS_WIFILI_TX_DESC_FREE_INV_BUFSRC,	/* Number of invalid bufsrc packets */
	NSS_STATS_WIFILI_TX_DESC_FREE_INV_COOKIE,	/* Number of invalid cookie packets */
	NSS_STATS_WIFILI_TX_DESC_FREE_HW_RING_EMPTY,	/* Number of time times hw ring empty found*/
	NSS_STATS_WIFILI_TX_DESC_FREE_REAPED,		/* Number of tx packets that are reaped out of tx completion ring */
	NSS_STATS_WIFILI_TX_DESC_FREE_MAX,		/* Number of tx comp stats */
};

/*
 * wifili tx reo stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *  	stats string array in nss_stats.c
 */
enum nss_stats_wifili_reo {
	NSS_STATS_WIFILI_REO_ERROR,			/* Number of reo error*/
	NSS_STATS_WIFILI_REO_REAPED,			/* Number of reo reaped*/
	NSS_STATS_WIFILI_REO_INV_COOKIE,		/* Number of invalid cookie*/
	NSS_STATS_WIFILI_REO_MAX,			/* Number of reo stats*/
};

/*
 * wifili tx desc stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_txsw_pool {
	NSS_STATS_WIFILI_TX_DESC_IN_USE,		/* Number of tx packets that are currently in flight */
	NSS_STATS_WIFILI_TX_DESC_ALLOC_FAIL,		/* Number of tx sw desc alloc failures */
	NSS_STATS_WIFILI_TX_DESC_ALREADY_ALLOCATED,	/* Number of tx sw desc already allocated*/
	NSS_STATS_WIFILI_TX_DESC_INVALID_FREE,		/* Number of tx sw desc invalid free*/
	NSS_STATS_WIFILI_TX_DESC_FREE_SRC_FW,		/* Number of tx desc for which release src is fw */
	NSS_STATS_WIFILI_TX_DESC_FREE_COMPLETION,	/* Number of tx desc completion*/
	NSS_STATS_WIFILI_TX_DESC_NO_PB,			/* Number of tx desc pb is null*/
	NSS_STATS_WIFILI_TX_DESC_MAX,			/* Number of tx desc stats*/
};

/*
 * wifili tx ext desc stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_ext_txsw_pool {
	NSS_STATS_WIFILI_EXT_TX_DESC_IN_USE,		/* Number of ext tx packets that are currently in flight */
	NSS_STATS_WIFILI_EXT_TX_DESC_ALLOC_FAIL,	/* Number of ext tx sw desc alloc failures */
	NSS_STATS_WIFILI_EXT_TX_DESC_ALREADY_ALLOCATED,	/* Number of ext tx sw desc already allocated*/
	NSS_STATS_WIFILI_EXT_TX_DESC_INVALID_FREE,	/* Number of ext tx sw desc invalid free*/
	NSS_STATS_WIFILI_EXT_TX_DESC_MAX,		/* Number of ext tx desc stats*/
};

/*
 * wifili rx desc stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_rxdma_pool {
	NSS_STATS_WIFILI_RX_DESC_NO_PB,			/* Number of rx desc no pb*/
	NSS_STATS_WIFILI_RX_DESC_ALLOC_FAIL,		/* Number of rx desc alloc failures */
	NSS_STATS_WIFILI_RX_DESC_IN_USE,		/* Number of rx desc alloc in use*/
	NSS_STATS_WIFILI_RX_DESC_MAX,			/* Number of rx desc stats*/
};

/*
 * wifili rx dma ring stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_rxdma_ring {
	NSS_STATS_WIFILI_RXDMA_DESC_UNAVAILABLE, 	/* Number of rx dma desc unavailable*/
	NSS_STATS_WIFILI_RXDMA_DESC_MAX,	 	/* Number of rx dma desc stast*/
};

/*
 * wifili wbm ring stats
 *
 * WARNING: There is a 1:1 mapping between values below and corresponding
 *	stats string array in nss_stats.c
 */
enum nss_stats_wifili_wbm {
	NSS_STATS_WIFILI_WBM_SRC_DMA,			/* Number of rx invalid src dma*/
	NSS_STATS_WIFILI_WBM_SRC_DMA_CODE_INV,		/* Number of rx invalid src dma*/
	NSS_STATS_WIFILI_WBM_SRC_REO,			/* Number of rx invalid src reo*/
	NSS_STATS_WIFILI_WBM_SRC_REO_CODE_NULLQ,	/* Number of rx invalid reo error with null q*/
	NSS_STATS_WIFILI_WBM_SRC_REO_CODE_INV,		/* Number of rx invalid reo error with null q*/
	NSS_STATS_WIFILI_WBM_SRC_INV,			/* Number of rx invalid reo code invalid*/
	NSS_STATS_WIFILI_WBM_MAX,			/* Number of rx wbm stats*/
};

/*
 * NSS core state -- for H2N/N2H
 * l2tpv2 debug stats
 */
enum nss_stats_l2tpv2_session {
	NSS_STATS_L2TPV2_SESSION_RX_PPP_LCP_PKTS,	/* Number of ppp lcp packets received */
	NSS_STATS_L2TPV2_SESSION_RX_EXP_DATA_PKTS,	/* Number of RX exceptioned packets */
	NSS_STATS_L2TPV2_SESSION_ENCAP_PBUF_ALLOC_FAIL_PKTS,	/* Number of times packet buffer allocation failed during encap */
	NSS_STATS_L2TPV2_SESSION_DECAP_PBUF_ALLOC_FAIL_PKTS,	/* Number of times packet buffer allocation failed during decap */
	NSS_STATS_L2TPV2_SESSION_MAX
};

/*
 * PortID statistics
 */
enum nss_stats_portid {
	NSS_STATS_PORTID_RX_INVALID_HEADER,
	NSS_STATS_PORTID_MAX,
};

struct nss_stats_l2tpv2_session_debug {
	uint64_t stats[NSS_STATS_L2TPV2_SESSION_MAX];
	int32_t if_index;
	uint32_t if_num; /* nss interface number */
	bool valid;
};

/*
 * PPTP debug stats
 */
enum nss_stats_pptp_session {
	NSS_STATS_PPTP_ENCAP_RX_PACKETS,
	NSS_STATS_PPTP_ENCAP_RX_BYTES,
	NSS_STATS_PPTP_ENCAP_TX_PACKETS,
	NSS_STATS_PPTP_ENCAP_TX_BYTES,
	NSS_STATS_PPTP_ENCAP_RX_DROP,
	NSS_STATS_PPTP_DECAP_RX_PACKETS,
	NSS_STATS_PPTP_DECAP_RX_BYTES,
	NSS_STATS_PPTP_DECAP_TX_PACKETS,
	NSS_STATS_PPTP_DECAP_TX_BYTES,
	NSS_STATS_PPTP_DECAP_RX_DROP,
	NSS_STATS_PPTP_SESSION_ENCAP_HEADROOM_ERR,
	NSS_STATS_PPTP_SESSION_ENCAP_SMALL_SIZE,
	NSS_STATS_PPTP_SESSION_ENCAP_PNODE_ENQUEUE_FAIL,
	NSS_STATS_PPTP_SESSION_DECAP_NO_SEQ_NOR_ACK,
	NSS_STATS_PPTP_SESSION_DECAP_INVAL_GRE_FLAGS,
	NSS_STATS_PPTP_SESSION_DECAP_INVAL_GRE_PROTO,
	NSS_STATS_PPTP_SESSION_DECAP_WRONG_SEQ,
	NSS_STATS_PPTP_SESSION_DECAP_INVAL_PPP_HDR,
	NSS_STATS_PPTP_SESSION_DECAP_PPP_LCP,
	NSS_STATS_PPTP_SESSION_DECAP_UNSUPPORTED_PPP_PROTO,
	NSS_STATS_PPTP_SESSION_DECAP_PNODE_ENQUEUE_FAIL,
	NSS_STATS_PPTP_SESSION_MAX
};

struct nss_stats_pptp_session_debug {
	uint64_t stats[NSS_STATS_PPTP_SESSION_MAX];
	int32_t if_index;
	uint32_t if_num; /* nss interface number */
	bool valid;
};

/*
 * PPE stats
 */
enum nss_stats_ppe_conn {
	NSS_STATS_PPE_V4_L3_FLOWS,		/* No of v4 routed flows */
	NSS_STATS_PPE_V4_L2_FLOWS,		/* No of v4 bridge flows */
	NSS_STATS_PPE_V4_CREATE_REQ,		/* No of v4 create requests */
	NSS_STATS_PPE_V4_CREATE_FAIL,		/* No of v4 create failure */
	NSS_STATS_PPE_V4_DESTROY_REQ,		/* No of v4 delete requests */
	NSS_STATS_PPE_V4_DESTROY_FAIL,		/* No of v4 delete failure */
	NSS_STATS_PPE_V4_MC_CREATE_REQ,		/* No of v4 MC create requests */
	NSS_STATS_PPE_V4_MC_CREATE_FAIL,	/* No of v4 MC create failure */
	NSS_STATS_PPE_V4_MC_UPDATE_REQ,		/* No of v4 MC update requests */
	NSS_STATS_PPE_V4_MC_UPDATE_FAIL,	/* No of v4 MC update failure */
	NSS_STATS_PPE_V4_MC_DESTROY_REQ,	/* No of v4 MC delete requests */
	NSS_STATS_PPE_V4_MC_DESTROY_FAIL,	/* No of v4 MC delete failure */

	NSS_STATS_PPE_V6_L3_FLOWS,		/* No of v6 routed flows */
	NSS_STATS_PPE_V6_L2_FLOWS,		/* No of v6 bridge flows */
	NSS_STATS_PPE_V6_CREATE_REQ,		/* No of v6 create requests */
	NSS_STATS_PPE_V6_CREATE_FAIL,		/* No of v6 create failure */
	NSS_STATS_PPE_V6_DESTROY_REQ,		/* No of v6 delete requests */
	NSS_STATS_PPE_V6_DESTROY_FAIL,		/* No of v6 delete failure */
	NSS_STATS_PPE_V6_MC_CREATE_REQ,		/* No of v6 MC create requests */
	NSS_STATS_PPE_V6_MC_CREATE_FAIL,	/* No of v6 MC create failure */
	NSS_STATS_PPE_V6_MC_UPDATE_REQ,		/* No of v6 MC update requests */
	NSS_STATS_PPE_V6_MC_UPDATE_FAIL,	/* No of v6 MC update failure */
	NSS_STATS_PPE_V6_MC_DESTROY_REQ,	/* No of v6 MC delete requests */
	NSS_STATS_PPE_V6_MC_DESTROY_FAIL,	/* No of v6 MC delete failure */

	NSS_STATS_PPE_FAIL_VP_FULL,		/* Create req fail due to VP table full */
	NSS_STATS_PPE_FAIL_NH_FULL,		/* Create req fail due to nexthop table full */
	NSS_STATS_PPE_FAIL_FLOW_FULL,		/* Create req fail due to flow table full */
	NSS_STATS_PPE_FAIL_HOST_FULL,		/* Create req fail due to host table full */
	NSS_STATS_PPE_FAIL_PUBIP_FULL,		/* Create req fail due to pub-ip table full */
	NSS_STATS_PPE_FAIL_PORT_SETUP,		/* Create req fail due to PPE port not setup */
	NSS_STATS_PPE_FAIL_RW_FIFO_FULL,	/* Create req fail due to rw fifo full */
	NSS_STATS_PPE_FAIL_FLOW_COMMAND,	/* Create req fail due to PPE flow command failure */
	NSS_STATS_PPE_FAIL_UNKNOWN_PROTO,	/* Create req fail due to unknown protocol */
	NSS_STATS_PPE_FAIL_PPE_UNRESPONSIVE,	/* Create req fail due to PPE not responding */
	NSS_STATS_PPE_CE_OPAQUE_INVALID,	/* Create req fail due to invalid opaque in CE */
	NSS_STATS_PPE_FAIL_FQG_FULL,		/* Create req fail due to flow qos group full */
	NSS_STATS_PPE_CONN_MAX
};

enum nss_stats_ppe_l3 {
	NSS_STATS_PPE_L3_DBG_0,		/* PPE L3 debug register 0 */
	NSS_STATS_PPE_L3_DBG_1,		/* PPE L3 debug register 1 */
	NSS_STATS_PPE_L3_DBG_2,		/* PPE L3 debug register 2 */
	NSS_STATS_PPE_L3_DBG_3,		/* PPE L3 debug register 3 */
	NSS_STATS_PPE_L3_DBG_4,		/* PPE L3 debug register 4 */
	NSS_STATS_PPE_L3_DBG_PORT,	/* PPE L3 debug register Port */
	NSS_STATS_PPE_L3_MAX
};

enum nss_stats_ppe_code {
	NSS_STATS_PPE_CODE_CPU,		/* PPE CPU code for last packet processed */
	NSS_STATS_PPE_CODE_DROP,	/* PPE DROP code for last packet processed */
	NSS_STATS_PPE_CODE_MAX
};

struct nss_stats_ppe_debug {
	uint32_t conn_stats[NSS_STATS_PPE_CONN_MAX];
	uint32_t l3_stats[NSS_STATS_PPE_L3_MAX];
	uint32_t code_stats[NSS_STATS_PPE_CODE_MAX];
	int32_t if_index;
	uint32_t if_num; /* nss interface number */
	bool valid;
};

/*
 * GRE base debug statistics types
 */
enum nss_stats_gre_base_debug_types {
	NSS_STATS_GRE_BASE_RX_PACKETS,			/**< Rx packet count. */
	NSS_STATS_GRE_BASE_RX_DROPPED,			/**< Rx dropped count. */
	NSS_STATS_GRE_BASE_EXP_ETH_HDR_MISSING,		/**< Ethernet header missing. */
	NSS_STATS_GRE_BASE_EXP_ETH_TYPE_NON_IP,		/**< Not IPV4 or IPV6 packet. */
	NSS_STATS_GRE_BASE_EXP_IP_UNKNOWN_PROTOCOL,	/**< Unknown protocol. */
	NSS_STATS_GRE_BASE_EXP_IP_HEADER_INCOMPLETE,	/**< Bad IP header. */
	NSS_STATS_GRE_BASE_EXP_IP_BAD_TOTAL_LENGTH,	/**< Invalid IP packet length. */
	NSS_STATS_GRE_BASE_EXP_IP_BAD_CHECKSUM,		/**< Bad packet checksum. */
	NSS_STATS_GRE_BASE_EXP_IP_DATAGRAM_INCOMPLETE,	/**< Bad packet. */
	NSS_STATS_GRE_BASE_EXP_IP_FRAGMENT,		/**< IP fragment. */
	NSS_STATS_GRE_BASE_EXP_IP_OPTIONS_INCOMPLETE,	/**< Invalid IP options. */
	NSS_STATS_GRE_BASE_EXP_IP_WITH_OPTIONS,		/**< IP packet with options. */
	NSS_STATS_GRE_BASE_EXP_IPV6_UNKNOWN_PROTOCOL,	/**< Unknown protocol. */
	NSS_STATS_GRE_BASE_EXP_IPV6_HEADER_INCOMPLETE,	/**< Incomplete IPV6 header. */
	NSS_STATS_GRE_BASE_EXP_GRE_UNKNOWN_SESSION,	/**< Unknown GRE session. */
	NSS_STATS_GRE_BASE_EXP_GRE_NODE_INACTIVE,	/**< GRE node inactive. */
	NSS_STATS_GRE_BASE_DEBUG_MAX,			/**< GRE base error max. */
};

/*
 *  GRE base debug statistics
 */
struct nss_stats_gre_base_debug {
	uint64_t stats[NSS_STATS_GRE_BASE_DEBUG_MAX];	/**< GRE debug statistics. */
};

/*
 * GRE session debug statistics types
 */
enum nss_stats_gre_session_debug_types {
	NSS_STATS_GRE_SESSION_PBUF_ALLOC_FAIL,			/**< Pbuf alloc failure. */
	NSS_STATS_GRE_SESSION_DECAP_FORWARD_ENQUEUE_FAIL,	/**< Rx forward enqueue failure. */
	NSS_STATS_GRE_SESSION_ENCAP_FORWARD_ENQUEUE_FAIL,	/**< Tx forward enqueue failure. */
	NSS_STATS_GRE_SESSION_DECAP_TX_FORWARDED,		/**< Packets forwarded after decap. */
	NSS_STATS_GRE_SESSION_ENCAP_RX_RECEIVED,		/**< Packets received for encap. */
	NSS_STATS_GRE_SESSION_ENCAP_RX_DROPPED,			/**< Packets dropped while enqueue for encap. */
	NSS_STATS_GRE_SESSION_ENCAP_RX_LINEAR_FAIL,		/**< Packets dropped during encap linearization. */
	NSS_STATS_GRE_SESSION_EXP_RX_KEY_ERROR,			/**< Rx KEY error. */
	NSS_STATS_GRE_SESSION_EXP_RX_SEQ_ERROR,			/**< Rx sequence number error. */
	NSS_STATS_GRE_SESSION_EXP_RX_CS_ERROR,			/**< Rx checksum error. */
	NSS_STATS_GRE_SESSION_EXP_RX_FLAG_MISMATCH,		/**< Rx flag mismatch. */
	NSS_STATS_GRE_SESSION_EXP_RX_MALFORMED,			/**< Rx malformed packet. */
	NSS_STATS_GRE_SESSION_EXP_RX_INVALID_PROTOCOL,		/**< Rx invalid protocol. */
	NSS_STATS_GRE_SESSION_EXP_RX_NO_HEADROOM,		/**< Rx no headroom. */
	NSS_STATS_GRE_SESSION_DEBUG_MAX,			/**< Session debug max. */
};

/*
 *  GRE session debug statistics
 */
struct nss_stats_gre_session_debug {
	uint64_t stats[NSS_STATS_GRE_SESSION_DEBUG_MAX];	/**< Session debug statistics. */
	int32_t if_index;					/**< Netdevice's ifindex. */
	uint32_t if_num;					/**< NSS interface number. */
	bool valid;						/**< Is node valid ? */
};

/*
 * MAP-T debug error types
 */
enum nss_stats_map_t_instance {
	NSS_STATS_MAP_T_V4_TO_V6_PBUF_EXCEPTION,
	NSS_STATS_MAP_T_V4_TO_V6_PBUF_NO_MATCHING_RULE,
	NSS_STATS_MAP_T_V4_TO_V6_PBUF_NOT_TCP_OR_UDP,
	NSS_STATS_MAP_T_V4_TO_V6_RULE_ERR_LOCAL_PSID,
	NSS_STATS_MAP_T_V4_TO_V6_RULE_ERR_LOCAL_IPV6,
	NSS_STATS_MAP_T_V4_TO_V6_RULE_ERR_REMOTE_PSID,
	NSS_STATS_MAP_T_V4_TO_V6_RULE_ERR_REMOTE_EA_BITS,
	NSS_STATS_MAP_T_V4_TO_V6_RULE_ERR_REMOTE_IPV6,
	NSS_STATS_MAP_T_V6_TO_V4_PBUF_EXCEPTION,
	NSS_STATS_MAP_T_V6_TO_V4_PBUF_NO_MATCHING_RULE,
	NSS_STATS_MAP_T_V6_TO_V4_PBUF_NOT_TCP_OR_UDP,
	NSS_STATS_MAP_T_V6_TO_V4_RULE_ERR_LOCAL_IPV4,
	NSS_STATS_MAP_T_V6_TO_V4_RULE_ERR_REMOTE_IPV4,
	NSS_STATS_MAP_T_MAX
};

/*
 * Trustsec TX statistics
 */
enum nss_stats_trustsec_tx {
	NSS_STATS_TRUSTSEC_TX_INVALID_SRC,
					/* Number of packets with invalid src if */
	NSS_STATS_TRUSTSEC_TX_UNCONFIGURED_SRC,
					/* Number of packets with unconfigured src if */
	NSS_STATS_IRUSTSEC_TX_HEADROOM_NOT_ENOUGH,
					/* Number of packets with not enough headroom */
	NSS_STATS_TRUSTSEC_TX_MAX
};

/*
 * NSS core stats -- for H2N/N2H map_t debug stats
 */
struct nss_stats_map_t_instance_debug {
	uint64_t stats[NSS_STATS_MAP_T_MAX];
	int32_t if_index;
	uint32_t if_num; /* nss interface number */
	bool valid;
};

/*
 * Types of EDMA Tx ring stats
 */
enum nss_stats_edma_tx_t {
	NSS_STATS_EDMA_TX_ERR,
	NSS_STATS_EDMA_TX_DROPPED,
	NSS_STATS_EDMA_TX_DESC,
	NSS_STATS_EDMA_TX_MAX
};

/*
 * Types of EDMA Rx ring stats
 */
enum nss_stats_edma_rx_t {
	NSS_STATS_EDMA_RX_CSUM_ERR,
	NSS_STATS_EDMA_RX_DESC,
	NSS_STATS_EDMA_RX_MAX
};

/*
 * Types of EDMA Tx complete stats
 */
enum nss_stats_edma_txcmpl_t {
	NSS_STATS_EDMA_TXCMPL_DESC,
	NSS_STATS_EDMA_TXCMPL_MAX
};

/*
 * Types of EDMA Rx fill stats
 */
enum nss_stats_edma_rxfill_t {
	NSS_STATS_EDMA_RXFILL_DESC,
	NSS_STATS_EDMA_RXFILL_MAX
};

/*
 * Port to EDMA ring map
 */
enum nss_edma_port_ring_map_t {
	NSS_EDMA_PORT_RX_RING,
	NSS_EDMA_PORT_TX_RING,
	NSS_EDMA_PORT_RING_MAP_MAX
};

/*
 * NSS EDMA port stats
 */
struct nss_edma_port_info {
	uint64_t port_stats[NSS_STATS_NODE_MAX];
	uint64_t port_type;
	uint64_t port_ring_map[NSS_EDMA_PORT_RING_MAP_MAX];
};

/*
 * NSS EDMA node statistics
 */
struct nss_edma_stats {
	struct nss_edma_port_info port[NSS_EDMA_NUM_PORTS_MAX];
	uint64_t tx_stats[NSS_EDMA_NUM_TX_RING_MAX][NSS_STATS_EDMA_TX_MAX];
	uint64_t rx_stats[NSS_EDMA_NUM_RX_RING_MAX][NSS_STATS_EDMA_RX_MAX];
	uint64_t txcmpl_stats[NSS_EDMA_NUM_TXCMPL_RING_MAX][NSS_STATS_EDMA_TXCMPL_MAX];
	uint64_t rxfill_stats[NSS_EDMA_NUM_RXFILL_RING_MAX][NSS_STATS_EDMA_RXFILL_MAX];
};

/*
 * NSS core state
 */
enum nss_core_state {
	NSS_CORE_STATE_UNINITIALIZED = 0,
	NSS_CORE_STATE_INITIALIZED,
	/*
	 * in following cases, only interrupts work
	 */
	NSS_CORE_STATE_FW_DEAD = 2,
	NSS_CORE_STATE_FW_DUMP = 4,
	NSS_CORE_STATE_PANIC = 8,
};

/*
 * Forward declarations
 */
struct nss_top_instance;
struct nss_ctx_instance;
struct int_ctx_instance;
struct net_dev_priv_instance;

/*
 * Network device private data instance
 */
struct netdev_priv_instance {
	struct int_ctx_instance *int_ctx;	/* Back pointer to interrupt context */
};

/*
 * Interrupt context instance (one per queue per NSS core)
 */
struct int_ctx_instance {
	struct nss_ctx_instance *nss_ctx;
					/* Back pointer to NSS context of core that
					   owns this interrupt */
	uint32_t irq[NSS_MAX_IRQ_PER_INSTANCE];
					/* HLOS IRQ numbers bind to this instance */
	uint32_t shift_factor;		/* Shift factor for this IRQ queue */
	uint32_t cause;			/* Interrupt cause carried forward to BH */
	uint32_t queue_cause;		/* Queue cause bind to this interrupt ctx */
	char irq_name[11];		/* IRQ name bind to this interrupt ctx */
	struct net_device *ndev;	/* Netdev associated with this interrupt ctx */
	struct napi_struct napi;	/* NAPI handler */
};

/*
 * N2H descriptor ring information
 */
struct hlos_n2h_desc_ring {
	struct n2h_desc_if_instance desc_ring;
					/* Descriptor ring */
	uint32_t hlos_index;		/* Current HLOS index for this ring */
	struct sk_buff *head;		/* First segment of an skb fraglist */
	struct sk_buff *tail;		/* Last segment received of an skb fraglist */
	struct sk_buff *jumbo_start;	/* First segment of an skb with frags[] */
};

/*
 * H2N descriptor ring information
 */
struct hlos_h2n_desc_rings {
	struct h2n_desc_if_instance desc_ring;	/* Descriptor ring */
	uint32_t hlos_index;
	spinlock_t lock;			/* Lock to save from simultaneous access */
	uint32_t flags;				/* Flags */
	uint64_t tx_q_full_cnt;			/* Descriptor queue full count */
};

#define NSS_H2N_DESC_RING_FLAGS_TX_STOPPED 0x1	/* Tx has been stopped for this queue */

/*
 * struct nss_shaper_bounce_registrant
 *	Registrant detail for shaper bounce operations
 */
struct nss_shaper_bounce_registrant {
	nss_shaper_bounced_callback_t bounced_callback;		/* Invoked for each shaper bounced packet returned from the NSS */
	void *app_data;						/* Argument given to the callback */
	struct module *owner;					/* Owning module of the callback + arg */
	bool registered;
	volatile bool callback_active;				/* true when the bounce callback is being called */
};

/*
 * NSS core <-> subsystem data plane registration related paramaters.
 *	This struct is filled with if_register/data_plane register APIs and
 *	retrieved when handling a data packet/skb destined to that subsystem.
 */
struct nss_subsystem_dataplane_register {
	nss_phys_if_rx_callback_t cb;	/* callback to be invoked */
	nss_phys_if_rx_ext_data_callback_t ext_cb;
					/* Extended data plane callback to be invoked.
					This is needed if driver needs extended handling of data packet
					before giving to stack */
	void *app_data;			/* additional info passed during callback(for future use) */
	struct net_device *ndev;	/* Netdevice associated with the interface */
	uint32_t features;		/* skb types supported by this subsystem */
};

/*
 * NSS context instance (one per NSS core)
 */
struct nss_ctx_instance {
	struct nss_top_instance *nss_top;
					/* Back pointer to NSS Top */
	struct device *dev;		/* Pointer to the original device from probe */
	uint32_t id;			/* Core ID for this instance */
	void __iomem *nmap;		/* Pointer to NSS CSM registers */
	void __iomem *vmap;		/* Virt mem pointer to virtual register map */
	void __iomem *qgic_map;	/* Virt mem pointer to QGIC register */
	uint32_t nphys;			/* Phys mem pointer to CSM register map */
	uint32_t vphys;			/* Phys mem pointer to virtual register map */
	uint32_t qgic_phys;		/* Phys mem pointer to QGIC register map */
	uint32_t load;			/* Load address for this core */
	enum nss_core_state state;	/* State of NSS core */
	uint32_t c2c_start;		/* C2C start address */
	struct int_ctx_instance int_ctx[NSS_MAX_DATA_QUEUE];
					/* Interrupt context instances for each queue */
	struct hlos_h2n_desc_rings h2n_desc_rings[NSS_H2N_DESC_RING_NUM];
					/* Host to NSS descriptor rings */
	struct hlos_n2h_desc_ring n2h_desc_ring[NSS_N2H_DESC_RING_NUM];
					/* NSS to Host descriptor rings */
	uint16_t n2h_rps_en;		/* N2H Enable Multiple queues for Data Packets */
	uint16_t n2h_mitigate_en;	/* N2H mitigation */
	uint32_t max_buf_size;		/* Maximum buffer size */
	uint32_t buf_sz_allocated;	/* size of bufs allocated from host */
	nss_cmn_queue_decongestion_callback_t queue_decongestion_callback[NSS_MAX_CLIENTS];
					/* Queue decongestion callbacks */
	void *queue_decongestion_ctx[NSS_MAX_CLIENTS];
					/* Queue decongestion callback contexts */
	spinlock_t decongest_cb_lock;	/* Lock to protect queue decongestion cb table */
	uint16_t phys_if_mtu[NSS_MAX_PHYSICAL_INTERFACES];
					/* Current MTU value of physical interface */
	uint64_t stats_n2h[NSS_STATS_N2H_MAX];
					/* N2H node stats: includes node, n2h, pbuf in this order */
	struct nss_subsystem_dataplane_register subsys_dp_register[NSS_MAX_NET_INTERFACES];
					/* Subsystem registration data */
	uint32_t magic;
					/* Magic protection */
};

/*
 * NSS wifili stats
 */
struct nss_wifili_stats {
	uint64_t stats_txrx[NSS_WIFILI_MAX_PDEV_NUM_MSG][NSS_STATS_WIFILI_TXRX_MAX];
							/* Number of txrx stats*/
	uint64_t stats_tcl_ring[NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG][NSS_STATS_WIFILI_TCL_MAX];
							/* Tcl stats for each ring*/
	uint64_t stats_tx_comp[NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG][NSS_STATS_WIFILI_TX_DESC_FREE_MAX];
							/* Tx comp ring stats*/
	uint64_t stats_tx_desc[NSS_WIFILI_MAX_TXDESC_POOLS_MSG][NSS_STATS_WIFILI_TX_DESC_MAX];
							/* Tx desc pool stats*/
	uint64_t stats_ext_tx_desc[NSS_WIFILI_MAX_TX_EXT_DESC_POOLS_MSG][NSS_STATS_WIFILI_EXT_TX_DESC_MAX];
							/* Tx ext desc pool stats*/
	uint64_t stats_reo[NSS_WIFILI_MAX_REO_DATA_RINGS_MSG][NSS_STATS_WIFILI_REO_MAX];
							/* Rx  reo ring stats*/
	uint64_t stats_rx_desc[NSS_WIFILI_MAX_PDEV_NUM_MSG][NSS_STATS_WIFILI_RX_DESC_MAX];
							/* Rx  rx sw pool stats*/
	uint64_t stats_rxdma[NSS_WIFILI_MAX_PDEV_NUM_MSG][NSS_STATS_WIFILI_RXDMA_DESC_MAX];
							/* Rx  dma ring stats*/
	uint64_t stats_wbm[NSS_STATS_WIFILI_WBM_MAX];
							/* Wbm  error ring stats*/
};

/*
 * Main NSS context structure (singleton)
 */
struct nss_top_instance {
	uint8_t num_nss;			/* Number of NSS cores supported */
	uint8_t num_phys_ports;			/* Number of physical ports supported */
	uint32_t clk_src;			/* Clock source: default/alternate */
	spinlock_t lock;			/* Big lock for NSS driver */
	spinlock_t stats_lock;			/* Statistics lock */
	struct mutex wq_lock;			/* Mutex for NSS Work queue function */
	struct dentry *top_dentry;		/* Top dentry for nss */
	struct dentry *stats_dentry;		/* Top dentry for nss stats */
	struct dentry *ipv4_dentry;		/* IPv4 stats dentry */
	struct dentry *ipv4_reasm_dentry;
						/* IPv4 reassembly stats dentry */
	struct dentry *ipv6_dentry;		/* IPv6 stats dentry */
	struct dentry *ipv6_reasm_dentry;
						/* IPv6 reassembly stats dentry */
	struct dentry *eth_rx_dentry;		/* ETH_RX stats dentry */
	struct dentry *n2h_dentry;		/* N2H stats dentry */
	struct dentry *lso_rx_dentry;		/* LSO_RX stats dentry */
	struct dentry *drv_dentry;		/* HLOS driver stats dentry */
	struct dentry *pppoe_dentry;		/* PPPOE stats dentry */
	struct dentry *pptp_dentry;		/* PPTP  stats dentry */
	struct dentry *l2tpv2_dentry;		/* L2TPV2  stats dentry */
	struct dentry *dtls_dentry;		/* DTLS stats dentry */
	struct dentry *gre_dentry;		/* GRE stats dentry */
	struct dentry *gre_tunnel_dentry;	/* GRE Tunnel stats dentry */
	struct dentry *map_t_dentry;		/* MAP-T stats dentry */
	struct dentry *gmac_dentry;		/* GMAC ethnode stats dentry */
	struct dentry *capwap_decap_dentry;	/* CAPWAP decap ethnode stats dentry */
	struct dentry *capwap_encap_dentry;	/* CAPWAP encap ethnode stats dentry */
	struct dentry *ppe_dentry;	/* PPE root dentry */
	struct dentry *ppe_conn_dentry;	/* PPE connection stats dentry */
	struct dentry *ppe_l3_dentry;	/* PPE L3 debug stats dentry */
	struct dentry *ppe_code_dentry;	/* PPE code stats dentry */
	struct dentry *gre_redir_dentry;	/* gre_redir ethnode stats dentry */
	struct dentry *sjack_dentry;		/* sjack stats dentry */
	struct dentry *trustsec_tx_dentry;	/* trustsec tx stats dentry */
	struct dentry *portid_dentry;		/* portid stats dentry */
	struct dentry *wifi_dentry;		/* wifi stats dentry */
	struct dentry *logs_dentry;		/* NSS FW logs directory */
	struct dentry *core_log_dentry;		/* NSS Core's FW log file */
	struct dentry *wifi_if_dentry;		/* wifi_if stats dentry */
	struct dentry *virt_if_dentry;		/* virt_if stats dentry */
	struct dentry *tx_rx_virt_if_dentry;	/* tx_rx_virt_if stats dentry. Will be deprecated soon */
	struct dentry *wifili_dentry;		/* wifili stats dentry */
	struct nss_ctx_instance nss[NSS_MAX_CORES];
						/* NSS contexts */
	/*
	 * Network processing handler core ids (CORE0/CORE1) for various interfaces
	 */
	uint8_t phys_if_handler_id[NSS_MAX_PHYSICAL_INTERFACES];
	uint8_t virt_if_handler_id[NSS_MAX_VIRTUAL_INTERFACES];
	uint8_t gre_redir_handler_id;
	uint8_t gre_tunnel_handler_id;
	uint8_t shaping_handler_id;
	uint8_t ipv4_handler_id;
	uint8_t ipv4_reasm_handler_id;
	uint8_t ipv6_handler_id;
	uint8_t ipv6_reasm_handler_id;
	uint8_t crypto_handler_id;
	uint8_t ipsec_handler_id;
	uint8_t wlan_handler_id;
	uint8_t tun6rd_handler_id;
	uint8_t wifi_handler_id;
	uint8_t ppe_handler_id;
	uint8_t pptp_handler_id;
	uint8_t l2tpv2_handler_id;
	uint8_t dtls_handler_id;
	uint8_t gre_handler_id;
	uint8_t map_t_handler_id;
	uint8_t tunipip6_handler_id;
	uint8_t frequency_handler_id;
	uint8_t sjack_handler_id;
	uint8_t capwap_handler_id;
	uint8_t tstamp_handler_id;
	uint8_t portid_handler_id;
	uint8_t oam_handler_id;
	uint8_t edma_handler_id;
	uint8_t bridge_handler_id;
	uint8_t trustsec_tx_handler_id;
	uint8_t vlan_handler_id;

	/*
	 * Data/Message callbacks for various interfaces
	 */
	nss_if_rx_msg_callback_t if_rx_msg_callback[NSS_MAX_NET_INTERFACES];
					/* All interfaces message callback functions */
	nss_phys_if_msg_callback_t phys_if_msg_callback[NSS_MAX_PHYSICAL_INTERFACES];
					/* Physical interface event callback functions */
	nss_virt_if_msg_callback_t virt_if_msg_callback[NSS_MAX_VIRTUAL_INTERFACES];
					/* Virtual interface messsage callback functions */
	nss_ipv4_msg_callback_t ipv4_callback;
					/* IPv4 sync/establish callback function */
	nss_ipv6_msg_callback_t ipv6_callback;
					/* IPv6 sync/establish callback function */
	nss_ipsec_msg_callback_t ipsec_encap_callback;
	nss_ipsec_msg_callback_t ipsec_decap_callback;
					/* IPsec event callback function */
	nss_crypto_msg_callback_t crypto_msg_callback;
	nss_crypto_cmn_msg_callback_t crypto_cmn_msg_callback;
	nss_crypto_buf_callback_t crypto_buf_callback;
	nss_crypto_pm_event_callback_t crypto_pm_callback;
					/* crypto interface callback functions */
	nss_profiler_callback_t profiler_callback[NSS_MAX_CORES];
					/* Profiler interface callback function */
	nss_tun6rd_msg_callback_t tun6rd_msg_callback;
					/* 6rd tunnel interface event callback function */
	nss_wifi_msg_callback_t wifi_msg_callback;
					/* wifi interface event callback function */
	nss_l2tpv2_msg_callback_t l2tpv2_msg_callback;
					/* l2tP tunnel interface event callback function */
	nss_dtls_msg_callback_t dtls_msg_callback; /* dtls interface event callback */

	nss_gre_tunnel_msg_callback_t gre_tunnel_msg_callback; /* gre tunnel interface event callback */

	nss_map_t_msg_callback_t map_t_msg_callback;
					/* map-t interface event callback function */
	nss_gre_msg_callback_t gre_msg_callback;
					/* gre interface event callback function */
	nss_gre_data_callback_t gre_data_callback;
					/* gre data callback function */
	nss_tunipip6_msg_callback_t tunipip6_msg_callback;
					/* ipip6 tunnel interface event callback function */
	nss_pptp_msg_callback_t pptp_msg_callback;
					/* PPTP tunnel interface event callback function */
	struct nss_shaper_bounce_registrant bounce_interface_registrants[NSS_MAX_NET_INTERFACES];
					/* Registrants for interface shaper bounce operations */
	struct nss_shaper_bounce_registrant bounce_bridge_registrants[NSS_MAX_NET_INTERFACES];
					/* Registrants for bridge shaper bounce operations */
	nss_lag_event_callback_t lag_event_callback;
					/* Registrants for lag operations */
	nss_oam_msg_callback_t oam_callback;
					/* OAM call back */
	nss_edma_msg_callback_t edma_callback;
					/* EDMA callback */
	nss_bridge_msg_callback_t bridge_callback;
					/* Bridge callback */
	nss_vlan_msg_callback_t vlan_callback;
					/* Vlan callback */
	nss_wifili_msg_callback_t wifili_msg_callback;
					/* wifili interface event callback function */
	uint32_t dynamic_interface_table[NSS_DYNAMIC_INTERFACE_TYPE_MAX];

	/*
	 * Interface contexts (non network device)
	 */
	void *ipv4_ctx;			/* IPv4 connection manager context */
	void *ipv6_ctx;			/* IPv6 connection manager context */
	void *crypto_ctx;		/* Crypto interface context */
	void *crypto_pm_ctx;		/* Crypto PM context */
	void *profiler_ctx[NSS_MAX_CORES];
					/* Profiler interface context */

	void *ipsec_encap_ctx;		/* IPsec encap context */
	void *ipsec_decap_ctx;		/* IPsec decap context */
	void *oam_ctx;			/* oam context */
	void *edma_ctx;			/* edma context */
	void *bridge_ctx;		/* Bridge context */
	void *vlan_ctx;			/* Vlan context */

	/*
	 * Statistics for various interfaces
	 */
	uint64_t stats_ipv4[NSS_STATS_IPV4_MAX];
					/* IPv4 statistics */
	uint64_t stats_ipv4_reasm[NSS_STATS_IPV4_REASM_MAX];
					/* IPv4 reasm statistics */
	uint64_t stats_ipv6[NSS_STATS_IPV6_MAX];
					/* IPv6 statistics */
	uint64_t stats_ipv6_reasm[NSS_STATS_IPV6_REASM_MAX];
					/* IPv6 reasm statistics */
	uint64_t stats_lso_rx[NSS_STATS_LSO_RX_MAX];
					/* LSO_RX statistics */
	atomic64_t stats_drv[NSS_STATS_DRV_MAX];
					/* Hlos driver statistics */
	uint64_t stats_pppoe[NSS_STATS_PPPOE_MAX];
					/* PPPoE statistics */
	uint64_t stats_gmac[NSS_MAX_PHYSICAL_INTERFACES][NSS_STATS_GMAC_MAX];
					/* GMAC statistics */
	uint64_t stats_wifi[NSS_MAX_WIFI_RADIO_INTERFACES][NSS_STATS_WIFI_MAX];
					/* WIFI statistics */
	uint64_t stats_eth_rx[NSS_STATS_ETH_RX_MAX];
					/* ETH_RX statistics */
	uint64_t stats_node[NSS_MAX_NET_INTERFACES][NSS_STATS_NODE_MAX];
					/* IPv4 statistics per interface */
	uint64_t stats_if_exception_eth_rx[NSS_EXCEPTION_EVENT_ETH_RX_MAX];
					/* Unknown protocol exception events per interface */
	uint64_t stats_if_exception_ipv4[NSS_EXCEPTION_EVENT_IPV4_MAX];
					/* IPv4 protocol exception events per interface */
	uint64_t stats_if_exception_ipv6[NSS_EXCEPTION_EVENT_IPV6_MAX];
					/* IPv6 protocol exception events per interface */
	uint64_t stats_if_exception_pppoe[NSS_MAX_PHYSICAL_INTERFACES + 1][NSS_PPPOE_NUM_SESSION_PER_INTERFACE + 1][NSS_PPPOE_EXCEPTION_EVENT_MAX];
					/* PPPoE exception events for per session on per interface. Interface and session indexes start with 1. */
	uint64_t stats_portid[NSS_STATS_PORTID_MAX];
					/* PortID statistics */
	struct nss_edma_stats stats_edma;
					/* EDMA node stats */
	uint64_t stats_trustsec_tx[NSS_STATS_TRUSTSEC_TX_MAX];
					/* Trustsec TX stats */

	struct nss_wifili_stats stats_wifili; /* Wifili stats*/
	bool nss_hal_common_init_done;

	uint16_t prev_mtu_sz;		/* mtu sz needed as of now */
	uint16_t crypto_enabled;	/* check if crypto is enabled on the platform */

	/*
	 * TODO: Review and update following fields
	 */
	uint64_t last_rx_jiffies;	/* Time of the last RX message from the NA in jiffies */
	struct nss_hal_ops *hal_ops;	/* nss_hal ops for this target platform */
	struct nss_data_plane_ops *data_plane_ops;
					/* nss_data_plane ops for this target platform */
};

#if (NSS_PKT_STATS_ENABLED == 1)
/*
 * nss_pkt_stats_increment()
 */
static inline void nss_pkt_stats_increment(struct nss_ctx_instance *nss_ctx, atomic64_t *stat)
{
	atomic64_inc(stat);
}

/*
 * nss_pkt_stats_increment()
 */
static inline void nss_pkt_stats_decrement(struct nss_ctx_instance *nss_ctx, atomic64_t *stat)
{
	atomic64_dec(stat);
}

/*
 * nss_pkt_stats_read()
 */
static inline uint64_t nss_pkt_stats_read(atomic64_t *stat)
{
	return atomic64_read(stat);
}

#endif

/*
 * NSS Statistics and Data for User Space
 */
struct nss_cmd_buffer {
	uint32_t current_freq;	/* Current Running Freq of NSS */
	int32_t auto_scale;	/* Enable or Disable auto_scale */
	int32_t max_freq;	/* Maximum supported frequency index value */
	uint32_t register_addr;	/* register addr buffer */
	uint32_t register_data;	/* register data buffer */
	uint32_t average_inst;	/* average of inst for nss core */
	uint32_t coredump;	/* cmd coredump buffer */
};
extern struct nss_cmd_buffer nss_cmd_buf;

/*
 * The scales for NSS
 */
typedef enum nss_freq_scales {
	NSS_FREQ_LOW_SCALE = 0,
	NSS_FREQ_MID_SCALE = 1,
	NSS_FREQ_HIGH_SCALE = 2,
	NSS_FREQ_MAX_SCALE = 3,
} nss_freq_scales_t;

/*
 * NSS Core Statistics and Frequencies
 */
#define NSS_SAMPLE_BUFFER_SIZE 4			/* Ring Buffer should be a Size of two */
#define NSS_SAMPLE_BUFFER_MASK (NSS_SAMPLE_BUFFER_SIZE - 1)
#define NSS_FREQUENCY_SCALE_RATE_LIMIT_UP 2		/* Adjust the Rate of Frequency Switching Up */
#define NSS_FREQUENCY_SCALE_RATE_LIMIT_DOWN 60000	/* Adjust the Rate of Frequency Switching Down */
#define NSS_MESSAGE_RATE_LIMIT 15000			/* Adjust the Rate of Displaying Statistic Messages */

/*
 * NSS Frequency Scale Info
 *
 * INFO: Contains the Scale information per Frequency
 *	Per Scale information needed to Program PLL and make switching decisions
 */
struct nss_scale_info {
	uint32_t frequency;	/* Frequency in Mhz */
	uint32_t minimum;	/* Minimum INST_CNT per Sec */
	uint32_t maximum;	/* Maximum INST_CNT per Sec */
};

/*
 * NSS Runtime Sample Structure
 *
 * INFO: Contains the runtime statistic of the NSS core
 *	Also contains the per frequency scale array
 */
struct nss_runtime_sampling {
	struct nss_scale_info freq_scale[NSS_FREQ_MAX_SCALE];	/* NSS Max Scale Per Freq */
	nss_freq_scales_t freq_scale_index;				/* Current Freq Index */
	uint32_t freq_scale_ready;				/* Allow Freq Scaling */
	uint32_t freq_scale_rate_limit_up;			/* Scaling Change Rate Limit */
	uint32_t freq_scale_rate_limit_down;			/* Scaling Change Rate Limit */
	uint32_t buffer[NSS_SAMPLE_BUFFER_SIZE];		/* Sample Ring Buffer */
	uint32_t buffer_index;					/* Running Buffer Index */
	uint32_t sum;						/* Total INST_CNT SUM */
	uint32_t sample_count;					/* Number of Samples stored in Ring Buffer */
	uint32_t average;					/* Average of INST_CNT */
	uint32_t message_rate_limit;				/* Debug Message Rate Limit */
	uint32_t initialized;					/* Flag to check for adequate initial samples */
};

#if (NSS_DT_SUPPORT == 1)
/*
 * nss_feature_enabled
 */
enum nss_feature_enabled {
	NSS_FEATURE_NOT_ENABLED = 0,		/* Feature is not enabled on this core */
	NSS_FEATURE_ENABLED,			/* Feature is enabled on this core */
};

/*
 * nss_platform_data
 *      Platform data per core
 */
struct nss_platform_data {
	uint32_t id;				/* NSS core ID */
	uint32_t num_queue;			/* No. of queues supported per core */
	uint32_t num_irq;			/* No. of irq binded per queue */
	uint32_t irq[NSS_MAX_IRQ_PER_CORE];	/* IRQ numbers per queue */
	void __iomem *nmap;			/* Virtual addr of NSS CSM space */
	void __iomem *vmap;			/* Virtual addr of NSS virtual register map */
	void __iomem *qgic_map;			/* Virtual addr of QGIC interrupt register */
	uint32_t nphys;				/* Physical addr of NSS CSM space */
	uint32_t vphys;				/* Physical addr of NSS virtual register map */
	uint32_t qgic_phys;			/* Physical addr of QGIC virtual register map */
	uint32_t load_addr;			/* Load address of NSS firmware */

	enum nss_feature_enabled capwap_enabled;
				/* Does this core handle capwap? */
	enum nss_feature_enabled crypto_enabled;
				/* Does this core handle crypto? */
	enum nss_feature_enabled dtls_enabled;
				/* Does this core handle DTLS sessions ? */
	enum nss_feature_enabled gre_redir_enabled;
				/* Does this core handle gre_redir Tunnel ? */
	enum nss_feature_enabled gre_tunnel_enabled;
				/* Does this core handle gre_tunnel Tunnel ? */
	enum nss_feature_enabled ipsec_enabled;
				/* Does this core handle IPsec? */
	enum nss_feature_enabled ipv4_enabled;
				/* Does this core handle IPv4? */
	enum nss_feature_enabled ipv4_reasm_enabled;
				/* Does this core handle IPv4 reassembly? */
	enum nss_feature_enabled ipv6_enabled;
				/* Does this core handle IPv6? */
	enum nss_feature_enabled ipv6_reasm_enabled;
				/* Does this core handle IPv6 reassembly? */
	enum nss_feature_enabled l2tpv2_enabled;
				/* Does this core handle l2tpv2 Tunnel ? */
	enum nss_feature_enabled map_t_enabled;
				/* Does this core handle map-t */
	enum nss_feature_enabled gre_enabled;
				/* Does this core handle GRE */
	enum nss_feature_enabled oam_enabled;
				/* Does this core handle oam? */
	enum nss_feature_enabled ppe_enabled;
				/* Does this core handle ppe ? */
	enum nss_feature_enabled pppoe_enabled;
				/* Does this core handle pppoe? */
	enum nss_feature_enabled pptp_enabled;
				/* Does this core handle pptp Tunnel ? */
	enum nss_feature_enabled portid_enabled;
				/* Does this core handle portid? */
	enum nss_feature_enabled shaping_enabled;
				/* Does this core handle shaping ? */
	enum nss_feature_enabled tstamp_enabled;
				/* Does this core handle timestamping? */
	enum nss_feature_enabled turbo_frequency;
				/* Does this core support turbo frequencies */
	enum nss_feature_enabled tun6rd_enabled;
				/* Does this core handle 6rd Tunnel ? */
	enum nss_feature_enabled tunipip6_enabled;
				/* Does this core handle ipip6 Tunnel ? */
	enum nss_feature_enabled wlanredirect_enabled;
				/* Does this core handle WLAN redirect? */
	enum nss_feature_enabled wifioffload_enabled;
				/* Does this core handle WIFI OFFLOAD? */
	enum nss_feature_enabled bridge_enabled;
				/* Does this core handle bridge configuration */
	enum nss_feature_enabled vlan_enabled;
				/* Does this core handle vlan configuration */
};
#endif

/*
 * nss_core_log_msg_failures()
 *	Driver function for logging failed messages.
 */
static inline void nss_core_log_msg_failures(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm)
{
	if ((ncm->response == NSS_CMN_RESPONSE_ACK) || (ncm->response == NSS_CMM_RESPONSE_NOTIFY)) {
		return;
	}

	/*
	 * TODO: Is it worth doing value to name on these values?
	 */
	nss_warning("%p: msg failure - interface: %d, type: %d, response: %d, error: %d",
		nss_ctx, ncm->interface, ncm->type, ncm->response, ncm->error);
}

/*
 * NSS workqueue to change frequencies
 */
typedef struct {
	struct work_struct my_work;	/* Work Structure */
	uint32_t frequency;		/* Frequency To Change */
	uint32_t stats_enable;		/* Auto scale on/off */
} nss_work_t;

/*
 * CB function declarations
 */
typedef void (*nss_core_rx_callback_t)(struct nss_ctx_instance *, struct nss_cmn_msg *, void *);

/*
 * APIs provided by nss_core.c
 */
extern int nss_core_handle_napi(struct napi_struct *napi, int budget);
extern int32_t nss_core_send_buffer(struct nss_ctx_instance *nss_ctx, uint32_t if_num,
					struct sk_buff *nbuf, uint16_t qid,
					uint8_t buffer_type, uint16_t flags);
extern void nss_wq_function( struct work_struct *work);
extern uint32_t nss_core_register_handler(uint32_t interface, nss_core_rx_callback_t cb, void *app_data);
extern uint32_t nss_core_unregister_handler(uint32_t interface);
extern int nss_core_max_ipv4_conn_get(void);
extern int nss_core_max_ipv6_conn_get(void);

static inline uint32_t nss_core_get_max_buf_size(struct nss_ctx_instance *nss_ctx)
{
	return nss_ctx->max_buf_size;
}

/*
 * APIs provided by nss_tx_rx.c
 */
extern void nss_rx_handle_status_pkt(struct nss_ctx_instance *nss_ctx, struct sk_buff *nbuf);

/*
 * APIs provided by nss_stats.c
 */
extern void nss_stats_init(void);
extern void nss_stats_clean(void);

/*
 * APIs provided by nss_log.c
 */
extern void nss_log_init(void);
extern bool nss_debug_log_buffer_alloc(uint8_t nss_id, uint32_t nentry);
extern int nss_logbuffer_handler(struct ctl_table *ctl, int write, void __user *buffer, size_t *lenp, loff_t *ppos);

/*
 * APIs to set jumbo_mru & paged_mode
 */
extern void nss_core_set_jumbo_mru(int jumbo_mru);
extern int nss_core_get_jumbo_mru(void);
extern void nss_core_set_paged_mode(int mode);
extern int nss_core_get_paged_mode(void);

/*
 * APIs for coredump
 */
extern void nss_coredump_notify_register(void);
extern void nss_fw_coredump_notify(struct nss_ctx_instance *nss_own, int intr);
extern int nss_coredump_init_delay_work(void);

/*
 * APIs provided by nss_freq.c
 */
extern bool nss_freq_sched_change(nss_freq_scales_t index, bool auto_scale);

/*
 * APIs for PPE
 */
extern void nss_ppe_init(void);
extern void nss_ppe_free(void);

#endif /* __NSS_CORE_H */

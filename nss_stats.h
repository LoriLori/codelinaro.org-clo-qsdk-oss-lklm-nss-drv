/*
 **************************************************************************
 * Copyright (c) 2016-2017, 2019-2020 The Linux Foundation. All rights reserved.
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
 * nss_stats.h
 *	printing stats header file
 */

#ifndef __NSS_STATS_PRINT_H
#define __NSS_STATS_PRINT_H
#include <linux/ctype.h>
#include <nss_drv_stats.h>
#include <nss_def.h>

/*
 * Defines to be used by single instance/core packages.
*/
#define NSS_STATS_SINGLE_CORE -1
#define NSS_STATS_SINGLE_INSTANCE -1

/*
 * Number of Extra outputlines for future reference to add new stats + start tag line + end tag line + three blank lines
 */
#define NSS_STATS_EXTRA_OUTPUT_LINES 35

/*
 * Maximum string length:
 * This should be equal to maximum string size of any stats
 * inclusive of stats value
 */
#define NSS_STATS_MAX_STR_LENGTH 96

/*
 * Node statistics
 *	Common stats for packet processing nodes.
 */
enum NSS_STATS_NODE {
	NSS_STATS_NODE_RX_PKTS,		/* Accelerated node RX packets */
	NSS_STATS_NODE_RX_BYTES,	/* Accelerated node RX bytes */
	NSS_STATS_NODE_TX_PKTS,		/* Accelerated node TX packets */
	NSS_STATS_NODE_TX_BYTES,	/* Accelerated node TX bytes */
	NSS_STATS_NODE_RX_QUEUE_0_DROPPED,
					/* Accelerated node RX Queue 0 dropped */
	NSS_STATS_NODE_RX_QUEUE_1_DROPPED,
					/* Accelerated node RX Queue 1 dropped */
	NSS_STATS_NODE_RX_QUEUE_2_DROPPED,
					/* Accelerated node RX Queue 2 dropped */
	NSS_STATS_NODE_RX_QUEUE_3_DROPPED,
					/* Accelerated node RX Queue 3 dropped */
	NSS_STATS_NODE_MAX,
};

/*
 * Stats_type
 *	List of stats categories.
 */
enum nss_stats_types {
	NSS_STATS_TYPE_COMMON,		/* Common pnode stats */
	NSS_STATS_TYPE_DROP,		/* Packet drop stats */
	NSS_STATS_TYPE_ERROR,		/* HW/SW errors different from drop or exception stats. */
					/* e.g. EDMA HW error, payload alloc failure */
	NSS_STATS_TYPE_EXCEPTION,	/* Packet exception (to host) stats */
	NSS_STATS_TYPE_SPECIAL,		/* Stats that don't fall into above types */
	NSS_STATS_TYPE_MAX
};

#define NSS_STATS_DECLARE_FILE_OPERATIONS(name) \
static const struct file_operations nss_##name##_stats_ops = { \
	.open = nss_stats_open, \
	.read = nss_##name##_stats_read, \
	.llseek = generic_file_llseek, \
	.release = nss_stats_release, \
};

/*
 * Private data for every file descriptor
 */
struct nss_stats_data {
	uint32_t if_num;	/**< Interface number for stats */
	uint32_t index;		/**< Index for GRE_REDIR stats */
	uint32_t edma_id;	/**< EDMA port ID or ring ID */
	struct nss_ctx_instance *nss_ctx;
				/**< The core for project stats */
};

/*
 * Structure definition carrying stats info.
 */
struct nss_stats_info {
	char stats_name[NSS_STATS_MAX_STR_LENGTH];	/* stat name */
	enum nss_stats_types stats_type;		/* enum that tags stat type  */
};

extern void nss_stats_register_sysctl(void);
void nss_stats_init(void);
extern int nss_stats_release(struct inode *inode, struct file *filp);
extern int nss_stats_open(struct inode *inode, struct file *filp);
void nss_stats_create_dentry(char *name, const struct file_operations *ops);
extern void nss_stats_reset_common_stats(uint32_t if_num);
extern size_t nss_stats_fill_common_stats(uint32_t if_num, int instance, char *lbuf, size_t size_wr, size_t size_al, char *node);
extern size_t nss_stats_banner(char *lbuf , size_t size_wr, size_t size_al, char *node, int core);
extern size_t nss_stats_print(char *node, char *stat_details, int instance, struct nss_stats_info *stats_info, uint64_t *stats_val, uint16_t max, char *lbuf, size_t size_wr, size_t size_al);
#endif /* __NSS_STATS_H */

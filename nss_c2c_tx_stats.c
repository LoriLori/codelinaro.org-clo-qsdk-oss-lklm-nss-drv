/*
 **************************************************************************
 * Copyright (c) 2018-2019, The Linux Foundation. All rights reserved.
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

#include "nss_core.h"
#include "nss_c2c_tx_stats.h"

/*
 * Spinlock to protect C2C_TX statistics update/read
 */
DEFINE_SPINLOCK(nss_c2c_tx_stats_lock);

/*
 * nss_c2c_tx_stats_str
 *	C2C_TX stats strings
 */
struct nss_stats_info nss_c2c_tx_stats_str[NSS_C2C_TX_STATS_MAX] = {
	{"rx_pkts"		, NSS_STATS_TYPE_COMMON},
	{"rx_byts"		, NSS_STATS_TYPE_COMMON},
	{"tx_pkts"		, NSS_STATS_TYPE_COMMON},
	{"tx_byts"		, NSS_STATS_TYPE_COMMON},
	{"rx_queue[0]_drops"	, NSS_STATS_TYPE_DROP},
	{"rx_queue[1]_drops"	, NSS_STATS_TYPE_DROP},
	{"rx_queue[2]_drops"	, NSS_STATS_TYPE_DROP},
	{"rx_queue[3]_drops"	, NSS_STATS_TYPE_DROP},
	{"pbuf_simple"		, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_sg"		, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_returning"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_c2c_tx_stats
 *	c2c_tx statistics
 */
uint64_t nss_c2c_tx_stats[NSS_MAX_CORES][NSS_C2C_TX_STATS_MAX];

/*
 * nss_c2c_tx_stats_read()
 *	Read c2c_tx statistics
 */
static ssize_t nss_c2c_tx_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i, core;

	/*
	 * Max output lines = #stats * NSS_MAX_CORES  +
	 * few blank lines for banner printing + Number of Extra outputlines for future reference to add new stats
	 */
	uint32_t max_output_lines = NSS_C2C_TX_STATS_MAX * NSS_MAX_CORES + NSS_STATS_EXTRA_OUTPUT_LINES;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return -ENOMEM;
	}

	stats_shadow = kzalloc(NSS_C2C_TX_STATS_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return -ENOMEM;
	}
	size_wr = nss_stats_banner(lbuf, size_wr, size_al, "c2c_tx");

	/*
	 * C2C_TX statistics
	 */
	for (core = 0; core < NSS_MAX_CORES; core++) {
		spin_lock_bh(&nss_c2c_tx_stats_lock);
		for (i = 0; i < NSS_C2C_TX_STATS_MAX; i++) {
			stats_shadow[i] = nss_c2c_tx_stats[core][i];
		}
		spin_unlock_bh(&nss_c2c_tx_stats_lock);
		size_wr = nss_stats_print("c2c_tx", NULL, core, NSS_STATS_SINGLE_INSTANCE, nss_c2c_tx_stats_str, stats_shadow, NSS_C2C_TX_STATS_MAX, lbuf, size_wr, size_al);
	}

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_c2c_tx_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(c2c_tx)

/*
 * nss_c2c_tx_stats_dentry_create()
 *	Create c2c_tx statistics debug entry.
 */
void nss_c2c_tx_stats_dentry_create(void)
{
	nss_stats_create_dentry("c2c_tx", &nss_c2c_tx_stats_ops);
}

/*
 * nss_c2c_tx_stats_sync()
 *	Handle the syncing of NSS C2C_TX statistics.
 */
void nss_c2c_tx_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_c2c_tx_stats *nct)
{
	int id = nss_ctx->id;
	int j;

	spin_lock_bh(&nss_c2c_tx_stats_lock);

	/*
	 * Common node stats
	 */
	nss_c2c_tx_stats[id][NSS_STATS_NODE_RX_PKTS] += (nct->pbuf_simple + nct->pbuf_sg + nct->pbuf_returning);
	nss_c2c_tx_stats[id][NSS_STATS_NODE_RX_BYTES] += nct->node_stats.rx_bytes;
	nss_c2c_tx_stats[id][NSS_STATS_NODE_TX_PKTS] += nct->node_stats.tx_packets;
	nss_c2c_tx_stats[id][NSS_STATS_NODE_TX_BYTES] += nct->node_stats.tx_bytes;

	for (j = 0; j < NSS_MAX_NUM_PRI; j++) {
		nss_c2c_tx_stats[id][NSS_STATS_NODE_RX_QUEUE_0_DROPPED + j] += nct->node_stats.rx_dropped[j];
	}

	/*
	 * C2C_TX statistics
	 */
	nss_c2c_tx_stats[id][NSS_C2C_TX_STATS_PBUF_SIMPLE] += nct->pbuf_simple;
	nss_c2c_tx_stats[id][NSS_C2C_TX_STATS_PBUF_SG] += nct->pbuf_sg;
	nss_c2c_tx_stats[id][NSS_C2C_TX_STATS_PBUF_RETURNING] += nct->pbuf_returning;

	spin_unlock_bh(&nss_c2c_tx_stats_lock);
}

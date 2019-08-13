/*
 **************************************************************************
 * Copyright (c) 2017, 2019 The Linux Foundation. All rights reserved.
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
#include "nss_eth_rx_stats.h"

/*
 * nss_eth_rx_stats_str
 *	eth_rx stats strings.
 */
struct nss_stats_info nss_eth_rx_stats_str[NSS_ETH_RX_STATS_MAX] = {
	{"ticks"	, NSS_STATS_TYPE_SPECIAL},
	{"worst_ticks"	, NSS_STATS_TYPE_SPECIAL},
	{"iterations"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_eth_rx_exception_stats_str
 *	Interface stats strings for unknown exceptions.
 */
struct nss_stats_info nss_eth_rx_exception_stats_str[NSS_ETH_RX_EXCEPTION_EVENT_MAX] = {
	{"unknown_l3_protocol"	, NSS_STATS_TYPE_EXCEPTION},
	{"eth_hdr_missing"	, NSS_STATS_TYPE_EXCEPTION},
	{"vlan_missing"		, NSS_STATS_TYPE_EXCEPTION},
	{"trustsec_hdr_missing"	, NSS_STATS_TYPE_EXCEPTION}
};

uint64_t nss_eth_rx_stats[NSS_ETH_RX_STATS_MAX];			/* ETH_RX statistics */
uint64_t nss_eth_rx_exception_stats[NSS_ETH_RX_EXCEPTION_EVENT_MAX];	/* Unknown protocol exception events per interface */

/*
 * nss_eth_rx_stats_read()
 *	Read ETH_RX stats.
 */
static ssize_t nss_eth_rx_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * Max output lines = #stats * NSS_MAX_CORES  +
	 * few blank lines for banner printing + Number of Extra outputlines for future reference to add new stats
	 */
	uint32_t max_output_lines = NSS_STATS_NODE_MAX + NSS_ETH_RX_STATS_MAX + NSS_ETH_RX_EXCEPTION_EVENT_MAX + NSS_STATS_EXTRA_OUTPUT_LINES;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats.
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = nss_stats_banner(lbuf, size_wr, size_al, "eth_rx");

	size_wr = nss_stats_fill_common_stats(NSS_ETH_RX_INTERFACE, lbuf, size_wr, size_al, "eth_rx");

	/*
	 * eth_rx node stats.
	 */
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_ETH_RX_STATS_MAX); i++) {
		stats_shadow[i] = nss_eth_rx_stats[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

  	size_wr = nss_stats_print("eth_rx", "eth_rx node stats", NSS_STATS_SINGLE_CORE, NSS_STATS_SINGLE_INSTANCE, nss_eth_rx_stats_str, stats_shadow, NSS_ETH_RX_STATS_MAX, lbuf, size_wr, size_al);

	/*
	 * Exception stats.
	 */
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_ETH_RX_EXCEPTION_EVENT_MAX); i++) {
		stats_shadow[i] = nss_eth_rx_exception_stats[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

  	size_wr = nss_stats_print("eth_rx", "eth_rx exception stats", NSS_STATS_SINGLE_CORE, NSS_STATS_SINGLE_INSTANCE, nss_eth_rx_exception_stats_str, stats_shadow, NSS_ETH_RX_EXCEPTION_EVENT_MAX, lbuf, size_wr, size_al);
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_eth_rx_stats_ops.
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(eth_rx)

/*
 * nss_eth_rx_stats_dentry_create()
 *	Create eth_rx statistics debug entry.
 */
void nss_eth_rx_stats_dentry_create(void)
{
	nss_stats_create_dentry("eth_rx", &nss_eth_rx_stats_ops);
}

/*
 * nss_eth_rx_metadata_stats_sync()
 *	Handle the syncing of ETH_RX node statistics.
 */
void nss_eth_rx_metadata_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_eth_rx_node_sync *nens)
{
	int32_t i;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_node[NSS_ETH_RX_INTERFACE][NSS_STATS_NODE_RX_PKTS] += nens->node_stats.rx_packets;
	nss_top->stats_node[NSS_ETH_RX_INTERFACE][NSS_STATS_NODE_RX_BYTES] += nens->node_stats.rx_bytes;
	nss_top->stats_node[NSS_ETH_RX_INTERFACE][NSS_STATS_NODE_TX_PKTS] += nens->node_stats.tx_packets;
	nss_top->stats_node[NSS_ETH_RX_INTERFACE][NSS_STATS_NODE_TX_BYTES] += nens->node_stats.tx_bytes;

	for (i = 0; i < NSS_MAX_NUM_PRI; i++) {
		nss_top->stats_node[NSS_ETH_RX_INTERFACE][NSS_STATS_NODE_RX_QUEUE_0_DROPPED + i] += nens->node_stats.rx_dropped[i];
	}

	nss_eth_rx_stats[NSS_ETH_RX_STATS_TOTAL_TICKS] += nens->total_ticks;
	nss_eth_rx_stats[NSS_ETH_RX_STATS_WORST_CASE_TICKS] += nens->worst_case_ticks;
	nss_eth_rx_stats[NSS_ETH_RX_STATS_ITERATIONS] += nens->iterations;

	for (i = 0; i < NSS_ETH_RX_EXCEPTION_EVENT_MAX; i++) {
		nss_eth_rx_exception_stats[i] += nens->exception_events[i];
	}

	spin_unlock_bh(&nss_top->stats_lock);
}

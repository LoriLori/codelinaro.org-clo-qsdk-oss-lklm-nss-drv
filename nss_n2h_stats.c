/*
 **************************************************************************
 * Copyright (c) 2017-2019, The Linux Foundation. All rights reserved.
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
#include "nss_n2h_stats.h"

/*
 * nss_n2h_stats_str
 *	N2H stats strings
 */
struct nss_stats_info nss_n2h_stats_str[NSS_N2H_STATS_MAX] = {
	{"rx_pkts"				, NSS_STATS_TYPE_COMMON},
	{"rx_byts"				, NSS_STATS_TYPE_COMMON},
	{"tx_pkts"				, NSS_STATS_TYPE_COMMON},
	{"tx_byts"				, NSS_STATS_TYPE_COMMON},
	{"rx_queue[0]_drops"			, NSS_STATS_TYPE_DROP},
	{"rx_queue[1]_drops"			, NSS_STATS_TYPE_DROP},
	{"rx_queue[2]_drops"			, NSS_STATS_TYPE_DROP},
	{"rx_queue[3]_drops"			, NSS_STATS_TYPE_DROP},
	{"queue_drops"				, NSS_STATS_TYPE_DROP},
	{"ticks"				, NSS_STATS_TYPE_SPECIAL},
	{"worst_ticks"				, NSS_STATS_TYPE_SPECIAL},
	{"iterations"				, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_ocm_total_count"			, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_ocm_free_count"			, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_ocm_alloc_fails_with_payload"	, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_ocm_alloc_fails_no_payload"	, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_default_free_count"		, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_default_total_count"		, NSS_STATS_TYPE_SPECIAL},
	{"pbuf_default_alloc_fails_with_payload", NSS_STATS_TYPE_SPECIAL},
	{"pbuf_default_alloc_fails_no_payload"	, NSS_STATS_TYPE_SPECIAL},
	{"payload_fails"			, NSS_STATS_TYPE_SPECIAL},
	{"payload_free_count"			, NSS_STATS_TYPE_SPECIAL},
	{"h2n_control_pkts"			, NSS_STATS_TYPE_SPECIAL},
	{"h2n_control_byts"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_control_pkts"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_control_byts"			, NSS_STATS_TYPE_SPECIAL},
	{"h2n_data_pkts"			, NSS_STATS_TYPE_SPECIAL},
	{"h2n_data_byts"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_data_pkts"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_data_byts"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_tot_payloads"			, NSS_STATS_TYPE_SPECIAL},
	{"n2h_data_interface_invalid"		, NSS_STATS_TYPE_SPECIAL},
	{"enqueue_retries"			, NSS_STATS_TYPE_SPECIAL}
};

uint64_t nss_n2h_stats[NSS_MAX_CORES][NSS_N2H_STATS_MAX];

/*
 * nss_n2h_stats_read()
 *	Read N2H stats
 */
static ssize_t nss_n2h_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i, core;

	/*
	 * Max output lines = #stats + few blank lines for banner printing +
	 * Number of Extra outputlines for future reference to add new stats
	 */
	uint32_t max_output_lines = (NSS_N2H_STATS_MAX + 3) * NSS_MAX_CORES + NSS_STATS_EXTRA_OUTPUT_LINES;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_N2H_STATS_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	/*
	 * N2H node stats
	 */
	for (core = 0; core < nss_top_main.num_nss; core++) {
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; i < NSS_N2H_STATS_MAX; i++) {
			stats_shadow[i] = nss_n2h_stats[core][i];
		}
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_banner(lbuf, size_wr, size_al, "n2h", core);
		size_wr += nss_stats_print("n2h", NULL, NSS_STATS_SINGLE_INSTANCE
						, nss_n2h_stats_str
						, stats_shadow
						, NSS_N2H_STATS_MAX
						, lbuf, size_wr, size_al);
	}

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_n2h_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(n2h)

/*
 * nss_n2h_stats_dentry_create()
 *	Create N2H statistics debug entry.
 */
void nss_n2h_stats_dentry_create(void)
{
	nss_stats_create_dentry("n2h", &nss_n2h_stats_ops);
}

/*
 * nss_n2h_stats_sync()
 *	Handle the syncing of NSS statistics.
 */
void nss_n2h_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_n2h_stats_sync *nnss)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	int id = nss_ctx->id;
	int j;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * common node stats
	 */
	nss_n2h_stats[id][NSS_STATS_NODE_RX_PKTS] += nnss->node_stats.rx_packets;
	nss_n2h_stats[id][NSS_STATS_NODE_RX_BYTES] += nnss->node_stats.rx_bytes;
	nss_n2h_stats[id][NSS_STATS_NODE_TX_PKTS] += nnss->node_stats.tx_packets;
	nss_n2h_stats[id][NSS_STATS_NODE_TX_BYTES] += nnss->node_stats.tx_bytes;

	for (j = 0; j < NSS_MAX_NUM_PRI; j++) {
		nss_n2h_stats[id][NSS_STATS_NODE_RX_QUEUE_0_DROPPED + j] += nnss->node_stats.rx_dropped[j];
	}

	/*
	 * General N2H stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_QUEUE_DROPPED] += nnss->queue_dropped;
	nss_n2h_stats[id][NSS_N2H_STATS_TOTAL_TICKS] += nnss->total_ticks;
	nss_n2h_stats[id][NSS_N2H_STATS_WORST_CASE_TICKS] += nnss->worst_case_ticks;
	nss_n2h_stats[id][NSS_N2H_STATS_ITERATIONS] += nnss->iterations;

	/*
	 * pbuf manager ocm and default pool stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_OCM_ALLOC_FAILS_WITH_PAYLOAD] += nnss->pbuf_ocm_stats.pbuf_alloc_fails_with_payload;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_OCM_FREE_COUNT] = nnss->pbuf_ocm_stats.pbuf_free_count;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_OCM_TOTAL_COUNT] = nnss->pbuf_ocm_stats.pbuf_total_count;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_OCM_ALLOC_FAILS_NO_PAYLOAD] += nnss->pbuf_ocm_stats.pbuf_alloc_fails_no_payload;

	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_DEFAULT_ALLOC_FAILS_WITH_PAYLOAD] += nnss->pbuf_default_stats.pbuf_alloc_fails_with_payload;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_DEFAULT_FREE_COUNT] = nnss->pbuf_default_stats.pbuf_free_count;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_DEFAULT_TOTAL_COUNT] = nnss->pbuf_default_stats.pbuf_total_count;
	nss_n2h_stats[id][NSS_N2H_STATS_PBUF_DEFAULT_ALLOC_FAILS_NO_PAYLOAD] += nnss->pbuf_default_stats.pbuf_alloc_fails_no_payload;

	/*
	 * payload mgr stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_PAYLOAD_ALLOC_FAILS] += nnss->payload_alloc_fails;
	nss_n2h_stats[id][NSS_N2H_STATS_PAYLOAD_FREE_COUNT] = nnss->payload_free_count;

	/*
	 * Host <=> NSS control traffic stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_H2N_CONTROL_PACKETS] += nnss->h2n_ctrl_pkts;
	nss_n2h_stats[id][NSS_N2H_STATS_H2N_CONTROL_BYTES] += nnss->h2n_ctrl_bytes;
	nss_n2h_stats[id][NSS_N2H_STATS_N2H_CONTROL_PACKETS] += nnss->n2h_ctrl_pkts;
	nss_n2h_stats[id][NSS_N2H_STATS_N2H_CONTROL_BYTES] += nnss->n2h_ctrl_bytes;

	/*
	 * Host <=> NSS control data traffic stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_H2N_DATA_PACKETS] += nnss->h2n_data_pkts;
	nss_n2h_stats[id][NSS_N2H_STATS_H2N_DATA_BYTES] += nnss->h2n_data_bytes;
	nss_n2h_stats[id][NSS_N2H_STATS_N2H_DATA_PACKETS] += nnss->n2h_data_pkts;
	nss_n2h_stats[id][NSS_N2H_STATS_N2H_DATA_BYTES] += nnss->n2h_data_bytes;

	/*
	 * Payloads related stats
	 */
	nss_n2h_stats[id][NSS_N2H_STATS_N2H_TOT_PAYLOADS] = nnss->tot_payloads;

	nss_n2h_stats[id][NSS_N2H_STATS_N2H_INTERFACE_INVALID] += nnss->data_interface_invalid;
	nss_n2h_stats[id][NSS_N2H_STATS_ENQUEUE_RETRIES] += nnss->enqueue_retries;

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 **************************************************************************
 * Copyright (c) 2013-2020, The Linux Foundation. All rights reserved.
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

/*
 * nss_drv_stats_str
 *	Host driver stats strings.
 */
struct nss_stats_info nss_drv_stats_str[NSS_DRV_STATS_MAX] = {
	{"nbuf_alloc_errors"		, NSS_STATS_TYPE_ERROR},
	{"paged_buf_alloc_errors"	, NSS_STATS_TYPE_ERROR},
	{"tx_queue_full[0]"		, NSS_STATS_TYPE_ERROR},
	{"tx_queue_full[1]"		, NSS_STATS_TYPE_ERROR},
	{"tx_buffers_empty"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_paged_buffers_empty"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffer_pkt"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_cmd"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_crypto"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_reuse"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_empty"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_pkt"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_ext_pkt"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_cmd_resp"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_status_sync"	, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_crypto"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_buffers_virtual"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_skb_simple"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_skb_nr_frags"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_skb_fraglist"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_skb_simple"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_skb_nr_frags"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_skb_fraglist"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_bad_desciptor"		, NSS_STATS_TYPE_ERROR},
	{"invalid_interface"		, NSS_STATS_TYPE_ERROR},
	{"invalid_core_id"		, NSS_STATS_TYPE_ERROR},
	{"invalid_buffer_type"		, NSS_STATS_TYPE_ERROR},
	{"nss_skb_count"		, NSS_STATS_TYPE_SPECIAL},
	{"rx_chain_seg_processed"	, NSS_STATS_TYPE_SPECIAL},
	{"rx_frag_seg_processed"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_cmd_queue_full"	, NSS_STATS_TYPE_ERROR},
#ifdef NSS_MULTI_H2N_DATA_RING_SUPPORT
	{"tx_buffers_data_queue[0]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[1]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[2]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[3]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[4]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[5]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[6]"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_buffers_data_queue[7]"	, NSS_STATS_TYPE_SPECIAL},
#endif
};

/*
 * nss_drv_stats_read()
 *	Read HLOS driver stats.
 */
ssize_t nss_drv_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * Max output lines = #stats * NSS_MAX_CORES  +
	 * few blank lines for banner printing + Number of Extra outputlines for future reference to add new stats
	 */
	uint32_t max_output_lines = NSS_DRV_STATS_MAX * NSS_MAX_CORES + NSS_STATS_EXTRA_OUTPUT_LINES;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_DRV_STATS_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr += nss_stats_banner(lbuf, size_wr, size_al, "drv", NSS_STATS_SINGLE_CORE);
	for (i = 0; (i < NSS_DRV_STATS_MAX); i++) {
		stats_shadow[i] = NSS_PKT_STATS_READ(&nss_top_main.stats_drv[i]);
	}

	size_wr += nss_stats_print("drv", NULL, NSS_STATS_SINGLE_INSTANCE, nss_drv_stats_str, stats_shadow, NSS_DRV_STATS_MAX, lbuf, size_wr, size_al);

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * TODO: Move this (nss_wt_stats_read) function to new file (nss_wt_stats.c)
 */

/*
 * nss_wt_stats_read()
 *	Reads and formats worker thread statistics and outputs them to ubuf
 */
ssize_t nss_wt_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = data->nss_ctx;
	struct nss_project_irq_stats *shadow;
	uint32_t thread_count = nss_ctx->worker_thread_count;
	uint32_t irq_count = nss_ctx->irq_count;

	/*
	 * Three lines for each IRQ
	 */
	uint32_t max_output_lines = thread_count * 3 * irq_count;
	size_t size_al = max_output_lines * NSS_STATS_MAX_STR_LENGTH;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	char *lbuf;
	int i;
	int j;

	lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer\n");
		return 0;
	}

	shadow = kzalloc(thread_count * irq_count * sizeof(struct nss_project_irq_stats), GFP_KERNEL);
	if (unlikely(!shadow)) {
		nss_warning("Could not allocate memory for stats shadow\n");
		kfree(lbuf);
		return 0;
	}

	spin_lock_bh(&nss_top_main.stats_lock);
	if (unlikely(!nss_ctx->wt_stats)) {
		spin_unlock_bh(&nss_top_main.stats_lock);
		nss_warning("Worker thread statistics not allocated\n");
		kfree(lbuf);
		kfree(shadow);
		return 0;
	}
	for (i = 0; i < thread_count; ++i) {

		/*
		 * The statistics shadow is an array with thread_count * irq_count
		 * items in it. Each item is located at the index:
		 *      (thread number) * (irq_count) + (irq number)
		 * thus simulating a two-dimensional array.
		 */
		for (j = 0; j < irq_count; ++j) {
			shadow[i * irq_count + j] = nss_ctx->wt_stats[i].irq_stats[j];
		}
	}
	spin_unlock_bh(&nss_top_main.stats_lock);

	size_wr += nss_stats_banner(lbuf, size_wr, size_al, "worker thread", NSS_STATS_SINGLE_CORE);
	for (i = 0; i < thread_count; ++i) {
		for (j = 0; j < irq_count; ++j) {
			struct nss_project_irq_stats *is = &(shadow[i * irq_count + j]);
			if (!(is->count)) {
				continue;
			}

			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d callback: 0x%x, count: %llu\n",
				i, j, is->callback, is->count);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d tick min: %10u  avg: %10u  max:%10u\n",
				i, j, is->ticks_min, is->ticks_avg, is->ticks_max);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d insn min: %10u  avg: %10u  max:%10u\n\n",
				i, j, is->insn_min, is->insn_avg, is->insn_max);
		}
	}
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(shadow);

	return bytes_read;
}

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

/*
 * nss_wifili_stats.c
 *	NSS wifili statistics APIs
 */

#include "nss_tx_rx_common.h"
#include "nss_core.h"
#include "nss_wifili_if.h"
#include "nss_wifili_stats.h"

/*
 * Maximum string length:
 * This should be equal to maximum string size of any stats
 * inclusive of stats value
 */
#define NSS_WIFILI_STATS_MAX	(NSS_WIFILI_STATS_TXRX_MAX + NSS_WIFILI_STATS_TCL_MAX + \
				NSS_WIFILI_STATS_TX_DESC_FREE_MAX + NSS_WIFILI_STATS_REO_MAX + \
				NSS_WIFILI_STATS_TX_DESC_MAX + NSS_WIFILI_STATS_EXT_TX_DESC_MAX + \
				NSS_WIFILI_STATS_RX_DESC_MAX + NSS_WIFILI_STATS_RXDMA_DESC_MAX)

/*
 * Statistics structures
 */
struct nss_wifili_stats stats_wifili;

/*
 * nss_wifili_stats_str_txrx
 *	wifili txrx statistics
 */
struct nss_stats_info nss_wifili_stats_str_txrx[NSS_WIFILI_STATS_TXRX_MAX] = {
	{"rx_msdu_error"			, NSS_STATS_TYPE_ERROR},
	{"rx_inv_peer_rcv"			, NSS_STATS_TYPE_SPECIAL},
	{"rx_wds_srcport_exception"		, NSS_STATS_TYPE_EXCEPTION},
	{"rx_wds_srcport_exception_fail"	, NSS_STATS_TYPE_DROP},
	{"rx_deliverd"				, NSS_STATS_TYPE_SPECIAL},
	{"rx_deliver_drops"			, NSS_STATS_TYPE_DROP},
	{"rx_intra_bss_ucast"			, NSS_STATS_TYPE_SPECIAL},
	{"rx_intra_bss_ucast_fail"		, NSS_STATS_TYPE_DROP},
	{"rx_intra_bss_mcast"			, NSS_STATS_TYPE_SPECIAL},
	{"rx_intra_bss_mcast_fail"		, NSS_STATS_TYPE_DROP},
	{"rx_sg_rcv_send"			, NSS_STATS_TYPE_SPECIAL},
	{"rx_sg_rcv_fail"			, NSS_STATS_TYPE_DROP},
	{"rx_mcast_echo"			, NSS_STATS_TYPE_SPECIAL},
	{"rx_inv_tid"				, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_inv_sc"			, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_inv_fc"			, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_non_frag"		, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_retry"			, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_ooo"			, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_ooo_seq"		, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_all_frag_rcv"		, NSS_STATS_TYPE_SPECIAL},
	{"stats_rx_frag_deliver"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_enqueue"				, NSS_STATS_TYPE_SPECIAL},
	{"tx_enqueue_drop"			, NSS_STATS_TYPE_DROP},
	{"tx_dequeue"				, NSS_STATS_TYPE_SPECIAL},
	{"tx_hw_enqueue_fail"			, NSS_STATS_TYPE_DROP},
	{"tx_sent_count"			, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_tcl
 *	wifili tcl stats
 */
struct nss_stats_info nss_wifili_stats_str_tcl[NSS_WIFILI_STATS_TCL_MAX] = {
	{"tcl_no_hw_desc"	, NSS_STATS_TYPE_SPECIAL},
	{"tcl_ring_full"	, NSS_STATS_TYPE_SPECIAL},
	{"tcl_ring_sent"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_tx_comp
 *	wifili tx comp stats
 */
struct nss_stats_info nss_wifili_stats_str_tx_comp[NSS_WIFILI_STATS_TX_DESC_FREE_MAX] = {
	{"tx_desc_free_inv_bufsrc"	, NSS_STATS_TYPE_ERROR},
	{"tx_desc_free_inv_cookie"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_free_hw_ring_empty"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_free_reaped"		, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_reo
 *	wifili tx reo stats
 */
struct nss_stats_info nss_wifili_stats_str_reo[NSS_WIFILI_STATS_REO_MAX] = {
	{"reo_error"		, NSS_STATS_TYPE_ERROR},
	{"reo_reaped"		, NSS_STATS_TYPE_SPECIAL},
	{"reo_inv_cookie"	, NSS_STATS_TYPE_SPECIAL},
	{"stats_reo_frag_rcv"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_txsw_pool
 *	wifili tx desc stats
 */
struct nss_stats_info nss_wifili_stats_str_txsw_pool[NSS_WIFILI_STATS_TX_DESC_MAX] = {
	{"tx_desc_in_use"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_alloc_fail"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_already_allocated"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_invalid_free"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_free_src_fw"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_free_completion"	, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_no_pb"		, NSS_STATS_TYPE_SPECIAL},
	{"tx_desc_queuelimit_drop"	, NSS_STATS_TYPE_DROP}
};

/*
 * nss_wifili_stats_str_ext_txsw_pool
 *	wifili tx ext desc stats
 */
struct nss_stats_info nss_wifili_stats_str_ext_txsw_pool[NSS_WIFILI_STATS_EXT_TX_DESC_MAX] = {
	{"ext_tx_desc_in_use"			, NSS_STATS_TYPE_SPECIAL},
	{"ext_tx_desc_alloc_fail"		, NSS_STATS_TYPE_SPECIAL},
	{"ext_tx_desc_already_allocated"	, NSS_STATS_TYPE_SPECIAL},
	{"ext_tx_desc_invalid_free"		, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_rxdma_pool
 *	wifili rx desc stats
 */
struct nss_stats_info nss_wifili_stats_str_rxdma_pool[NSS_WIFILI_STATS_RX_DESC_MAX] = {
	{"rx_desc_no_pb"	, NSS_STATS_TYPE_SPECIAL},
	{"rx_desc_alloc_fail"	, NSS_STATS_TYPE_SPECIAL},
	{"rx_desc_in_use"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_rxdma_ring
 *	wifili rx dma ring stats
 */
struct nss_stats_info nss_wifili_stats_str_rxdma_ring[NSS_WIFILI_STATS_RXDMA_DESC_MAX] = {
	{"rxdma_hw_desc_unavailable"	, NSS_STATS_TYPE_SPECIAL},
	{"rxdma_buf_replenished"	, NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_wifili_stats_str_wbm
 *	wifili wbm ring stats
 */
struct nss_stats_info nss_wifili_stats_str_wbm[NSS_WIFILI_STATS_WBM_MAX] = {
	{"wbm_src_dma"			, NSS_STATS_TYPE_SPECIAL},
	{"wbm_src_dma_code_inv"		, NSS_STATS_TYPE_SPECIAL},
	{"wbm_src_reo"			, NSS_STATS_TYPE_SPECIAL},
	{"wbm_src_reo_code_nullq"	, NSS_STATS_TYPE_SPECIAL},
	{"wbm_src_reo_code_inv"		, NSS_STATS_TYPE_ERROR},
	{"wbm_src_inv"			, NSS_STATS_TYPE_ERROR}
};

/*
 * nss_wifili_stats_read()
 *	Read wifili statistics
 */
static ssize_t nss_wifili_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i;

	/*
	 * max output lines = ((#stats + eight blank lines) * #WIFILI #STATS) + start/end tag + 3 blank
	 * + Number of Extra outputlines for future reference to add new stats
	 */
	uint32_t max_output_lines = (((NSS_WIFILI_STATS_MAX + 9) * NSS_WIFILI_MAX_PDEV_NUM_MSG)+
									NSS_WIFILI_STATS_WBM_MAX + NSS_STATS_EXTRA_OUTPUT_LINES);
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
	 * Take max of all wifili stats
	 *
	 * NOTE: txrx stats is bigger of all stats
	 */
	stats_shadow = kzalloc(NSS_WIFILI_STATS_TXRX_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr += nss_stats_banner(lbuf, size_wr, size_al, "wifili", NSS_STATS_SINGLE_CORE);

	for (i = 0; i < NSS_WIFILI_MAX_PDEV_NUM_MSG; i++) {

		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_txrx
						, stats_shadow
						, NSS_WIFILI_STATS_TXRX_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TCL ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_tcl
						, stats_shadow
						, NSS_WIFILI_STATS_TCL_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TCL comp stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_tx_comp
						, stats_shadow
						, NSS_WIFILI_STATS_TX_DESC_FREE_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng reo ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_reo
						, stats_shadow
						, NSS_WIFILI_STATS_REO_MAX
						, lbuf, size_wr, size_al);

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TX SW Pool
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_txsw_pool
						, stats_shadow
						, NSS_WIFILI_STATS_TX_DESC_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TX  EXt SW Pool
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_ext_txsw_pool
						, stats_shadow
						, NSS_WIFILI_STATS_EXT_TX_DESC_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng rxdma pool stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili", NULL, i
						, nss_wifili_stats_str_rxdma_pool
						, stats_shadow
						, NSS_WIFILI_STATS_RX_DESC_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng rxdma ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili",  NULL, i
						, nss_wifili_stats_str_rxdma_ring
						, stats_shadow
						, NSS_WIFILI_STATS_RXDMA_DESC_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
		/*
		 * Fillinng wbm ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		size_wr += nss_stats_print("wifili",  NULL, i
						, nss_wifili_stats_str_wbm
						, stats_shadow
						, NSS_WIFILI_STATS_WBM_MAX
						, lbuf, size_wr, size_al);
		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * wifili_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(wifili)

/*
 * nss_wifili_stats_dentry_create()
 *	Create wifili statistics debug entry.
 */
void nss_wifili_stats_dentry_create(void)
{
	nss_stats_create_dentry("wifili", &nss_wifili_stats_ops);
}

/*
 * nss_wifili_stats_sync()
 *	Handle the syncing of WIFI stats.
 */
void nss_wifili_stats_sync(struct nss_ctx_instance *nss_ctx,
		struct nss_wifili_stats_sync_msg *wlsoc_stats, uint16_t interface)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_wifili_stats *stats = &stats_wifili;
	struct nss_wifili_device_stats *devstats = &wlsoc_stats->stats;
	uint32_t index;

	spin_lock_bh(&nss_top->stats_lock);

	for (index = 0; index < NSS_WIFILI_MAX_PDEV_NUM_MSG; index++) {
		/*
		 * Rx stats
		 */
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_MSDU_ERROR] +=
							devstats->rx_data_stats[index].rx_msdu_err;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_INV_PEER_RCV] +=
							(devstats->rx_data_stats[index].rx_inv_peer +
							devstats->rx_data_stats[index].rx_scatter_inv_peer);
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_WDS_SRCPORT_EXCEPTION] +=
							devstats->rx_data_stats[index].rx_wds_learn_send;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_WDS_SRCPORT_EXCEPTION_FAIL] +=
							devstats->rx_data_stats[index].rx_wds_learn_send_fail;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_DELIVERD] +=
							devstats->rx_data_stats[index].rx_deliver_cnt;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_DELIVER_DROPPED] +=
							devstats->rx_data_stats[index].rx_deliver_cnt_fail;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_INTRA_BSS_UCAST] +=
							devstats->rx_data_stats[index].rx_intra_bss_ucast_send;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_INTRA_BSS_UCAST_FAIL] +=
							devstats->rx_data_stats[index].rx_intra_bss_ucast_send_fail;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_INTRA_BSS_MCAST] +=
							devstats->rx_data_stats[index].rx_intra_bss_mcast_send;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_INTRA_BSS_MCAST_FAIL] +=
							devstats->rx_data_stats[index].rx_intra_bss_mcast_send_fail;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_SG_RCV_SEND] +=
							devstats->rx_data_stats[index].rx_sg_recv_send;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_SG_RCV_FAIL] +=
							devstats->rx_data_stats[index].rx_sg_recv_fail;
		stats->stats_txrx[index][NSS_STATS_WIFILI_RX_MCAST_ECHO] +=
							devstats->rx_data_stats[index].rx_me_pkts;
		stats->stats_txrx[index][NSS_STATS_WIFILI_RX_INV_TID] +=
							devstats->rx_data_stats[index].rx_inv_tid;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_INV_SC] +=
							devstats->rx_data_stats[index].rx_frag_inv_sc;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_INV_FC] +=
							devstats->rx_data_stats[index].rx_frag_inv_fc;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_NON_FRAG] +=
							devstats->rx_data_stats[index].rx_non_frag_err;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_RETRY] +=
							devstats->rx_data_stats[index].rx_repeat_fragno;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_OOO] +=
							devstats->rx_data_stats[index].rx_ooo_frag;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_OOO_SEQ] +=
							devstats->rx_data_stats[index].rx_ooo_frag_seq;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_ALL_FRAG_RCV] +=
							devstats->rx_data_stats[index].rx_all_frag_rcv;
		stats->stats_txrx[index][NSS_WIFILI_STATS_RX_FRAG_DELIVER] +=
							devstats->rx_data_stats[index].rx_frag_deliver;

		/*
		 * Tx stats
		 */
		stats->stats_txrx[index][NSS_WIFILI_STATS_TX_ENQUEUE] +=
							devstats->tx_data_stats[index].tx_enqueue_cnt;
		stats->stats_txrx[index][NSS_WIFILI_STATS_TX_ENQUEUE_DROP] +=
							devstats->tx_data_stats[index].tx_enqueue_dropped;
		stats->stats_txrx[index][NSS_WIFILI_STATS_TX_DEQUEUE] +=
							devstats->tx_data_stats[index].tx_dequeue_cnt;
		stats->stats_txrx[index][NSS_WIFILI_STATS_TX_HW_ENQUEUE_FAIL] +=
							devstats->tx_data_stats[index].tx_send_fail_cnt;
		stats->stats_txrx[index][NSS_WIFILI_STATS_TX_SENT_COUNT] +=
							devstats->tx_data_stats[index].tx_processed_pkt;
	}

	/*
	 * update the tcl ring stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG; index++) {
		stats->stats_tcl_ring[index][NSS_WIFILI_STATS_TCL_NO_HW_DESC] +=
							devstats->tcl_stats[index].tcl_no_hw_desc;
		stats->stats_tcl_ring[index][NSS_WIFILI_STATS_TCL_RING_FULL] +=
							devstats->tcl_stats[index].tcl_ring_full;
		stats->stats_tcl_ring[index][NSS_WIFILI_STATS_TCL_RING_SENT] +=
							devstats->tcl_stats[index].tcl_ring_sent;
	}

	/*
	 * update the tcl comp stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_TCL_DATA_RINGS_MSG; index++) {
		stats->stats_tx_comp[index][NSS_WIFILI_STATS_TX_DESC_FREE_INV_BUFSRC] +=
								devstats->txcomp_stats[index].invalid_bufsrc;
		stats->stats_tx_comp[index][NSS_WIFILI_STATS_TX_DESC_FREE_INV_COOKIE] +=
								devstats->txcomp_stats[index].invalid_cookie;
		stats->stats_tx_comp[index][NSS_WIFILI_STATS_TX_DESC_FREE_HW_RING_EMPTY] +=
								devstats->txcomp_stats[index].hw_ring_empty;
		stats->stats_tx_comp[index][NSS_WIFILI_STATS_TX_DESC_FREE_REAPED] +=
								devstats->txcomp_stats[index].ring_reaped;
	}

	/*
	 * update reo ring stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_REO_DATA_RINGS_MSG; index++) {
		stats->stats_reo[index][NSS_WIFILI_STATS_REO_ERROR] +=
								devstats->rxreo_stats[index].ring_error;
		stats->stats_reo[index][NSS_WIFILI_STATS_REO_REAPED] +=
								devstats->rxreo_stats[index].ring_reaped;
		stats->stats_reo[index][NSS_WIFILI_STATS_REO_INV_COOKIE] +=
								devstats->rxreo_stats[index].invalid_cookie;
		stats->stats_reo[index][NSS_WIFILI_STATS_REO_FRAG_RCV] +=
								devstats->rxreo_stats[index].defrag_reaped;
	}

	/*
	 * update tx sw pool
	 */
	for (index = 0; index < NSS_WIFILI_MAX_TXDESC_POOLS_MSG; index++) {
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_IN_USE] =
								devstats->tx_sw_pool_stats[index].desc_alloc;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_ALLOC_FAIL] +=
								devstats->tx_sw_pool_stats[index].desc_alloc_fail;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_ALREADY_ALLOCATED] +=
								devstats->tx_sw_pool_stats[index].desc_already_allocated;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_INVALID_FREE] +=
								devstats->tx_sw_pool_stats[index].desc_invalid_free;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_FREE_SRC_FW] +=
								devstats->tx_sw_pool_stats[index].tx_rel_src_fw;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_FREE_COMPLETION] +=
								devstats->tx_sw_pool_stats[index].tx_rel_tx_desc;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_DESC_NO_PB] +=
								devstats->tx_sw_pool_stats[index].tx_rel_no_pb;
		stats->stats_tx_desc[index][NSS_WIFILI_STATS_TX_QUEUELIMIT_DROP] +=
								devstats->tx_sw_pool_stats[index].tx_queue_limit_drop;
	}

	/*
	 * update ext tx desc pool stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_TX_EXT_DESC_POOLS_MSG; index++) {
		stats->stats_ext_tx_desc[index][NSS_WIFILI_STATS_EXT_TX_DESC_IN_USE] =
								devstats->tx_ext_sw_pool_stats[index].desc_alloc;
		stats->stats_ext_tx_desc[index][NSS_WIFILI_STATS_EXT_TX_DESC_ALLOC_FAIL] +=
								devstats->tx_ext_sw_pool_stats[index].desc_alloc_fail;
		stats->stats_ext_tx_desc[index][NSS_WIFILI_STATS_EXT_TX_DESC_ALREADY_ALLOCATED] +=
								devstats->tx_ext_sw_pool_stats[index].desc_already_allocated;
		stats->stats_ext_tx_desc[index][NSS_WIFILI_STATS_EXT_TX_DESC_INVALID_FREE] +=
								devstats->tx_ext_sw_pool_stats[index].desc_invalid_free;
	}

	/*
	 * update rx desc pool stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_PDEV_NUM_MSG; index++) {
		stats->stats_rx_desc[index][NSS_WIFILI_STATS_RX_DESC_NO_PB] +=
								devstats->rx_sw_pool_stats[index].rx_no_pb;
		stats->stats_rx_desc[index][NSS_WIFILI_STATS_RX_DESC_ALLOC_FAIL] +=
								devstats->rx_sw_pool_stats[index].desc_alloc_fail;
		stats->stats_rx_desc[index][NSS_WIFILI_STATS_RX_DESC_IN_USE] =
								devstats->rx_sw_pool_stats[index].desc_alloc;
	}

	/*
	 * update rx dma ring stats
	 */
	for (index = 0; index < NSS_WIFILI_MAX_PDEV_NUM_MSG; index++) {
		stats->stats_rxdma[index][NSS_WIFILI_STATS_RXDMA_DESC_UNAVAILABLE] +=
								devstats->rxdma_stats[index].rx_hw_desc_unavailable;
	}

	/*
	 * update wbm ring stats
	 */
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_DMA] += devstats->rxwbm_stats.err_src_rxdma;
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_DMA_CODE_INV] += devstats->rxwbm_stats.err_src_rxdma_code_inv;
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_REO] += devstats->rxwbm_stats.err_src_reo;
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_REO_CODE_NULLQ] += devstats->rxwbm_stats.err_src_reo_code_nullq;
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_REO_CODE_INV] += devstats->rxwbm_stats.err_src_reo_code_inv;
	stats->stats_wbm[NSS_WIFILI_STATS_WBM_SRC_INV] += devstats->rxwbm_stats.err_src_invalid;
	spin_unlock_bh(&nss_top->stats_lock);
	return;
}


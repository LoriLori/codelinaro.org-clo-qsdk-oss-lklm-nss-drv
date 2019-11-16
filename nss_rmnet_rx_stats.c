/*
 **************************************************************************
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include "nss_stats.h"
#include "nss_core.h"
#include "nss_rmnet_rx_stats.h"

/*
 * Data structure that holds the virtual interface context.
 */
extern struct nss_rmnet_rx_handle *rmnet_rx_handle[];

/*
 * Spinlock to protect the global data structure virt_handle.
 */
extern spinlock_t nss_rmnet_rx_lock;

/*
 * nss_rmnet_rx_stats_str
 *	rmnet_rx interface stats strings
 */
static int8_t *nss_rmnet_rx_stats_str[NSS_RMNET_RX_STATS_MAX] = {
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes",
	"rx_queue_0_dropped",
	"rx_queue_1_dropped",
	"rx_queue_2_dropped",
	"rx_queue_3_dropped",
	"enqueue failed",
	"no available channel",
	"linear pbuf count",
	"no pbuf to linear",
	"no enough room",
	"channel[0]",
	"channel[1]",
	"channel[2]",
	"channel[3]",
	"channel[4]",
	"channel[5]",
	"channel[6]",
	"channel[7]",
	"channel[8]",
	"channel[9]",
	"channel[10]",
	"channel[11]",
	"DMA full"
};

/*
 * nss_rmnet_rx_stats_fill_row()
 *	Fill one row of rmnet_rx stats.
 */
static int32_t nss_rmnet_rx_stats_fill_row(char *line, int len, int start, struct nss_rmnet_rx_stats *stats)
{
	uint64_t tcnt = 0;

	switch (start) {
	case NSS_RMNET_RX_STATS_RX_PKTS:
		tcnt = stats->node_stats.rx_packets;
		break;

	case NSS_RMNET_RX_STATS_RX_BYTES:
		tcnt = stats->node_stats.rx_bytes;
		break;

	case NSS_RMNET_RX_STATS_TX_PKTS:
		tcnt = stats->node_stats.tx_packets;
		break;

	case NSS_RMNET_RX_STATS_TX_BYTES:
		tcnt = stats->node_stats.tx_bytes;
		break;

	case NSS_RMNET_RX_STATS_QUEUE_0_DROPPED:
		tcnt = stats->node_stats.rx_dropped[0];
		break;

	case NSS_RMNET_RX_STATS_QUEUE_1_DROPPED:
		tcnt = stats->node_stats.rx_dropped[1];
		break;

	case NSS_RMNET_RX_STATS_QUEUE_2_DROPPED:
		tcnt = stats->node_stats.rx_dropped[2];
		break;

	case NSS_RMNET_RX_STATS_QUEUE_3_DROPPED:
		tcnt = stats->node_stats.rx_dropped[3];
		break;

	case NSS_RMNET_RX_STATS_ENQUEUE_FAILED:
		tcnt = stats->enqueue_failed;
		break;

	case NSS_RMNET_RX_STATS_NO_AVAIL_CHANNEL:
		tcnt = stats->no_avail_channel;
		break;

	case NSS_RMNET_RX_STATS_NUM_LINEAR_PBUF:
		tcnt = stats->num_linear_pbuf;
		break;

	case NSS_RMNET_RX_STATS_NO_PBUF_TO_LINEAR:
		tcnt = stats->no_pbuf_to_linear;
		break;

	case NSS_RMNET_RX_STATS_NO_ENOUGH_ROOM:
		tcnt = stats->no_enough_room;
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL0:
		tcnt = stats->using_channel[0];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL1:
		tcnt = stats->using_channel[1];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL2:
		tcnt = stats->using_channel[2];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL3:
		tcnt = stats->using_channel[3];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL4:
		tcnt = stats->using_channel[4];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL5:
		tcnt = stats->using_channel[5];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL6:
		tcnt = stats->using_channel[6];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL7:
		tcnt = stats->using_channel[7];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL8:
		tcnt = stats->using_channel[8];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL9:
		tcnt = stats->using_channel[9];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL10:
		tcnt = stats->using_channel[10];
		break;

	case NSS_RMNET_RX_STATS_USING_CHANNEL11:
		tcnt = stats->using_channel[11];
		break;

	case NSS_RMNET_RX_STATS_DMA_FAILED:
		tcnt = stats->dma_failed;
		break;

	default:
		return 0;
	}

	return scnprintf(line, len, "%s = %llu\n", nss_rmnet_rx_stats_str[start], tcnt);
}

/*
 * nss_rmnet_rx_stats_get()
 *	Get rmnet_rx interface stats by interface number.
 */
static bool nss_rmnet_rx_stats_get(struct nss_ctx_instance *nss_ctx, uint32_t if_num, void *stats, bool is_base)
{
	uint32_t if_num_curr = if_num;
	if_num = if_num - NSS_DYNAMIC_IF_START;

	spin_lock_bh(&nss_rmnet_rx_lock);
	if (!rmnet_rx_handle[if_num]) {
		spin_unlock_bh(&nss_rmnet_rx_lock);
		return false;
	}

	if (if_num_curr == rmnet_rx_handle[if_num]->if_num_n2h) {
		memcpy((struct nss_rmnet_rx_stats *)stats,
			&rmnet_rx_handle[if_num]->stats_n2h,
			sizeof(struct nss_rmnet_rx_stats));
		spin_unlock_bh(&nss_rmnet_rx_lock);
		return true;
	}

	memcpy((struct nss_rmnet_rx_stats *)stats,
		&rmnet_rx_handle[if_num]->stats_h2n,
		sizeof(struct nss_rmnet_rx_stats));
	spin_unlock_bh(&nss_rmnet_rx_lock);
	return true;
}

/*
 * nss_rmnet_rx_stats_read()
 *	Read rmnet_rx statistics
 */
static ssize_t nss_rmnet_rx_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = nss_rmnet_rx_get_context();
	int32_t if_num = NSS_DYNAMIC_IF_START;
	int32_t max_if_num = if_num + NSS_MAX_DYNAMIC_INTERFACES;
	size_t bytes = 0;
	ssize_t bytes_read = 0;
	char line[80];
	int start, end;
	int32_t if_num_valid = NSS_DYNAMIC_IF_START - 1;
	struct nss_rmnet_rx_stats stats_local;

	if (data) {
		if_num = data->if_num;
	}

	if (if_num > max_if_num) {
		return 0;
	}

	/*
	 * Interface statistics for all interfaces.
	 */
	for (; if_num < max_if_num; if_num++) {

		if (!nss_rmnet_rx_stats_get(nss_ctx, if_num, &stats_local, false))
			continue;

		bytes = scnprintf(line, sizeof(line), "if_num %d stats start:\n\n", if_num);
		if ((bytes_read + bytes) > sz)
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0)
			return -EFAULT;

		bytes_read += bytes;

		start = NSS_RMNET_RX_STATS_RX_PKTS;
		end = NSS_RMNET_RX_STATS_MAX;
		while (bytes_read < sz && start < end) {
			bytes = nss_rmnet_rx_stats_fill_row(line, sizeof(line), start, &stats_local);
			if (!bytes)
				break;

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0)
				return -EFAULT;

			bytes_read += bytes;
			start++;
		}

		/*
		 * Save one valid interface number for base node statistics.
		 */
		if_num_valid = if_num;

		bytes = scnprintf(line, sizeof(line), "if_num %d stats end:\n\n", if_num);
		if (bytes_read > (sz - bytes))
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0)
			return -EFAULT;

		bytes_read += bytes;
	}

	if (data) {
		data->if_num = if_num;
	}

	return bytes_read;
}

/*
 * nss_rmnet_rx_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(rmnet_rx)

/*
 * nss_rmnet_rx_stats_dentry_create()
 *	Create rmnet_rx statistics debug entry.
 */
void nss_rmnet_rx_stats_dentry_create(void)
{
	nss_stats_create_dentry("rmnet_rx", &nss_rmnet_rx_stats_ops);
}

/*
 * nss_rmnet_rx_stats_sync()
 *	Sync stats from the NSS FW
 */
void nss_rmnet_rx_stats_sync(struct nss_rmnet_rx_handle *handle,
			     struct nss_rmnet_rx_stats *nwis, uint32_t if_num)
{
	int i;
	struct nss_rmnet_rx_stats *stats;
	spin_lock_bh(&nss_rmnet_rx_lock);
	if (if_num == handle->if_num_n2h) {
		stats = &handle->stats_n2h;
	} else {
		stats = &handle->stats_h2n;
	}

	stats->node_stats.rx_packets += nwis->node_stats.rx_packets;
	stats->node_stats.rx_bytes += nwis->node_stats.rx_bytes;
	stats->node_stats.tx_packets += nwis->node_stats.tx_packets;
	stats->node_stats.tx_bytes += nwis->node_stats.tx_bytes;

	for (i = 0; i < NSS_MAX_NUM_PRI; i++) {
		stats->node_stats.rx_dropped[i] += nwis->node_stats.rx_dropped[i];
	}

	stats->enqueue_failed += nwis->enqueue_failed;
	stats->no_avail_channel += nwis->no_avail_channel;
	stats->num_linear_pbuf += nwis->num_linear_pbuf;
	stats->no_pbuf_to_linear += nwis->no_pbuf_to_linear;
	stats->no_enough_room += nwis->no_enough_room;

	for (i = 0; i < NSS_RMNET_RX_CHANNEL_MAX; i++) {
		stats->using_channel[i] += nwis->using_channel[i];
	}

	stats->dma_failed += nwis->dma_failed;
	spin_unlock_bh(&nss_rmnet_rx_lock);
}

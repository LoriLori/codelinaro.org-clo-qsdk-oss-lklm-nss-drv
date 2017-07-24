/*
 **************************************************************************
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
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
#include "nss_stats.h"
#include "nss_gre_redir.h"
#include "nss_gre_redir_stats.h"

/*
 * nss_gre_redir_stats_str
 *	GRE REDIR statistics string
 */
static int8_t *nss_gre_redir_stats_str[NSS_GRE_REDIR_STATS_MAX] = {
	"TX Packets",
	"TX Bytes",
	"TX Drops",
	"RX Packets",
	"RX Bytes",
	"Rx Drops"
};

/*
 * nss_gre_redir_stats()
 *	Make a row for GRE_REDIR stats.
 */
static ssize_t nss_gre_redir_stats(char *line, int len, int i, struct nss_gre_redir_tunnel_stats *s)
{
	char name[20];
	uint64_t tcnt = 0;
	int j = 0;

	switch (i) {
	case 0:
		tcnt = s->node_stats.tx_packets;
		return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
	case 1:
		tcnt = s->node_stats.tx_bytes;
		return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
	case 2:
		tcnt = s->tx_dropped;
		return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
	case 3:
		tcnt = s->node_stats.rx_packets;
		return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
	case 4:
		tcnt = s->node_stats.rx_bytes;
		return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
	case 5:
		for (j = 0; j < NSS_MAX_NUM_PRI; j++) {
			scnprintf(name, 20, "Rx Queue %d Drops", j);
			tcnt += snprintf(line, len, "%s = %u\n", name, s->node_stats.rx_dropped[j]);
		}
		return tcnt;

	default:
		return 0;
	}

	return snprintf(line, len, "%s = %llu\n", nss_gre_redir_stats_str[i], tcnt);
}

/*
 * nss_gre_redir_stats_read()
 *	READ gre_redir tunnel stats.
 */
static ssize_t nss_gre_redir_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	ssize_t bytes_read = 0;
	struct nss_gre_redir_tunnel_stats stats;
	size_t bytes;
	char line[80];
	int start, end;
	int index = 0;

	if (data) {
		index = data->index;
	}

	/*
	 * If we are done accomodating all the GRE_REDIR tunnels.
	 */
	if (index >= NSS_GRE_REDIR_MAX_INTERFACES) {
		return 0;
	}

	for (; index < NSS_GRE_REDIR_MAX_INTERFACES; index++) {
		bool isthere;

		/*
		 * If gre_redir tunnel does not exists, then isthere will be false.
		 */
		isthere = nss_gre_redir_get_stats(index, &stats);
		if (!isthere) {
			continue;
		}

		bytes = snprintf(line, sizeof(line), "\nTunnel if_num: %2d\n", stats.if_num);
		if ((bytes_read + bytes) > sz) {
			break;
		}

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto fail;
		}
		bytes_read += bytes;
		start = 0;
		end = 6;
		while (bytes_read < sz && start < end) {
			bytes = nss_gre_redir_stats(line, sizeof(line), start, &stats);

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto fail;
			}

			bytes_read += bytes;
			start++;
		}
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->index = index;
	}

fail:
	return bytes_read;
}

/*
 * nss_gre_redir_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gre_redir)

void nss_gre_redir_stats_dentry_create(void)
{
	nss_stats_create_dentry("gre_redir", &nss_gre_redir_stats_ops);
}

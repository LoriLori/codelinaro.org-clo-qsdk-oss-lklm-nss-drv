/*
 **************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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

#include "nss_stats.h"
#include "nss_core.h"
#include "nss_strings.h"
#include "nss_clmap_strings.h"

/*
 * nss_clmap_strings_stats
 *	Clmap statistics strings for nss tunnel stats
 */
struct nss_stats_info nss_clmap_stats_str[NSS_CLMAP_INTERFACE_STATS_MAX] = {
	{"rx_pkts",					NSS_STATS_TYPE_COMMON},
	{"rx_bytes",					NSS_STATS_TYPE_COMMON},
	{"tx_pkts",					NSS_STATS_TYPE_COMMON},
	{"tx_bytes",					NSS_STATS_TYPE_COMMON},
	{"rx_queue_0_dropped",				NSS_STATS_TYPE_DROP},
	{"rx_queue_1_dropped",				NSS_STATS_TYPE_DROP},
	{"rx_queue_2_dropped",				NSS_STATS_TYPE_DROP},
	{"rx_queue_3_dropped",				NSS_STATS_TYPE_DROP},
	{"MAC DB look up failed",			NSS_STATS_TYPE_SPECIAL},
	{"Invalid packet count",			NSS_STATS_TYPE_SPECIAL},
	{"Headroom drop",				NSS_STATS_TYPE_SPECIAL},
	{"Next node queue full drop",			NSS_STATS_TYPE_SPECIAL},
	{"Pbuf alloc failed drop",			NSS_STATS_TYPE_SPECIAL},
	{"Linear failed drop",				NSS_STATS_TYPE_SPECIAL},
	{"Shared packet count",				NSS_STATS_TYPE_SPECIAL},
	{"Ethernet frame error",			NSS_STATS_TYPE_SPECIAL},
	{"Macdb create requests count",			NSS_STATS_TYPE_SPECIAL},
	{"Macdb create failures MAC exists count",	NSS_STATS_TYPE_SPECIAL},
	{"Macdb create failures MAC table full count",	NSS_STATS_TYPE_SPECIAL},
	{"Macdb destroy requests count",		NSS_STATS_TYPE_SPECIAL},
	{"Macdb destroy failures MAC not found count",	NSS_STATS_TYPE_SPECIAL},
	{"Macdb destroy failures MAC unhashed count",	NSS_STATS_TYPE_SPECIAL},
	{"Macdb flush requests count",			NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_clmap_stats_str_strings_read()
 *	Read clmap statistics names
 */
static ssize_t nss_clmap_stats_str_strings_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_strings_print(ubuf, sz, ppos, nss_clmap_stats_str, NSS_CLMAP_INTERFACE_STATS_MAX);
}

/*
 * nss_clmap_stats_str_strings_ops
 */
NSS_STRINGS_DECLARE_FILE_OPERATIONS(clmap_stats_str);

/*
 * nss_clmap_interface_type_str
 *	Clmap interface type string.
 */
struct nss_stats_info nss_clmap_interface_type_str[NSS_CLMAP_INTERFACE_TYPE_MAX] = {
	{"Upstream",	NSS_STATS_TYPE_SPECIAL},
	{"Downstream",	NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_clmap_interface_type_str_strings_read()
 *	Read clmap interface type names
 */
static ssize_t nss_clmap_interface_type_str_strings_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_strings_print(ubuf, sz, ppos, nss_clmap_interface_type_str, NSS_CLMAP_INTERFACE_TYPE_MAX);
}

/*
 * nss_clmap_interface_type_str_strings_ops
 */
NSS_STRINGS_DECLARE_FILE_OPERATIONS(clmap_interface_type_str);

/*
 * nss_clmap_strings_dentry_create()
 *	Create clmap statistics strings debug entry.
 */
void nss_clmap_strings_dentry_create(void)
{
	struct dentry *clmap_d = NULL;
	struct dentry *clmap_stats_str_d = NULL;
	struct dentry *clmap_interface_type_str_d = NULL;

	if (!nss_top_main.strings_dentry) {
		nss_warning("qca-nss-drv/strings is not present");
		return;
	}

	clmap_d = debugfs_create_dir("clmap", nss_top_main.strings_dentry);
	if (!clmap_d) {
		nss_warning("Failed to create qca-nss-drv/strings/clmap directory");
		return;
	}

	clmap_stats_str_d = debugfs_create_file("stats_str", 0400, clmap_d, &nss_top_main,
						&nss_clmap_stats_str_strings_ops);
	if (!clmap_stats_str_d) {
		nss_warning("Failed to create qca-nss-drv/strings/clmap/stats_str file");
		debugfs_remove_recursive(clmap_d);
		return;
	}

	clmap_interface_type_str_d = debugfs_create_file("interface_type_str", 0400, clmap_d, &nss_top_main,
							&nss_clmap_interface_type_str_strings_ops);
	if (!clmap_interface_type_str_d) {
		nss_warning("Failed to create qca-nss-drv/strings/clmap/interface_type_str file");
		debugfs_remove_recursive(clmap_d);
		return;
	}
}

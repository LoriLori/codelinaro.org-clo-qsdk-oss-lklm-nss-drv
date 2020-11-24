/*
 ***************************************************************************
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
 ***************************************************************************
 */

#include "nss_stats.h"
#include "nss_core.h"
#include "nss_strings.h"
#include "nss_gre_redir_mark_strings.h"

/*
 * nss_gre_redir_mark_stats_str
 *	GRE redir mark statistics string
 */
struct nss_stats_info nss_gre_redir_mark_stats_str[NSS_GRE_REDIR_MARK_STATS_MAX] = {
	{"TX Packets",				NSS_STATS_TYPE_COMMON},
	{"TX Bytes",				NSS_STATS_TYPE_COMMON},
	{"RX Packets",				NSS_STATS_TYPE_COMMON},
	{"RX Bytes",				NSS_STATS_TYPE_COMMON},
	{"RX Drops",				NSS_STATS_TYPE_DROP},
	{"HLOS Magic Failed",			NSS_STATS_TYPE_SPECIAL},
	{"Tx Inv_dst_if Drops",			NSS_STATS_TYPE_DROP},
	{"Tx Dst_if Enqueue",			NSS_STATS_TYPE_SPECIAL},
	{"Tx Dst_if Enqueue Drops",		NSS_STATS_TYPE_DROP},
	{"Invalid Appid",			NSS_STATS_TYPE_SPECIAL},
	{"Headroom Unavailable",		NSS_STATS_TYPE_EXCEPTION},
	{"Tx Completion Host Enqueue Success",	NSS_STATS_TYPE_SPECIAL},
	{"Tx Completion Host Enqueue Drops",	NSS_STATS_TYPE_DROP}
};

/*
 * nss_gre_redir_mark_stats_str_strings_read()
 *	Read gre_redir_mark statistics names
 */
static ssize_t nss_gre_redir_mark_stats_str_strings_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_strings_print(ubuf, sz, ppos, nss_gre_redir_mark_stats_str, NSS_GRE_REDIR_MARK_STATS_MAX);
}

/*
 * nss_gre_redir_mark_stats_str_strings_ops
 */
NSS_STRINGS_DECLARE_FILE_OPERATIONS(gre_redir_mark_stats_str);

/*
 * nss_gre_redir_mark_strings_dentry_create()
 *	Create gre_redir_mark statistics strings debug entry.
 */
void nss_gre_redir_mark_strings_dentry_create(void)
{
	nss_strings_create_dentry("gre_redir_mark_stats_str", &nss_gre_redir_mark_stats_str_strings_ops);
}

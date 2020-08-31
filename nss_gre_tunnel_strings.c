/*
 ****************************************************************************
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
 ****************************************************************************
 */

#include "nss_stats.h"
#include "nss_core.h"
#include "nss_strings.h"
#include "nss_gre_tunnel_strings.h"

/*
 * nss_gre_tunnel_stats_session_debug_str
 *	GRE Tunnel statistics strings for nss session stats
 */
struct nss_stats_info nss_gre_tunnel_stats_session_debug_str[NSS_GRE_TUNNEL_STATS_SESSION_MAX] = {
	{"RX_PKTS",			NSS_STATS_TYPE_COMMON},
	{"TX_PKTS",			NSS_STATS_TYPE_COMMON},
	{"RX_QUEUE_0_DROPPED",		NSS_STATS_TYPE_DROP},
	{"RX_QUEUE_1_DROPPED",		NSS_STATS_TYPE_DROP},
	{"RX_QUEUE_2_DROPPED",		NSS_STATS_TYPE_DROP},
	{"RX_QUEUE_3_DROPPED",		NSS_STATS_TYPE_DROP},
	{"RX_MALFORMED",		NSS_STATS_TYPE_SPECIAL},
	{"RX_INVALID_PROT",		NSS_STATS_TYPE_SPECIAL},
	{"DECAP_QUEUE_FULL",		NSS_STATS_TYPE_SPECIAL},
	{"RX_SINGLE_REC_DGRAM",		NSS_STATS_TYPE_SPECIAL},
	{"RX_INVALID_REC_DGRAM",	NSS_STATS_TYPE_SPECIAL},
	{"BUFFER_ALLOC_FAIL",		NSS_STATS_TYPE_SPECIAL},
	{"BUFFER_COPY_FAIL",		NSS_STATS_TYPE_SPECIAL},
	{"OUTFLOW_QUEUE_FULL",		NSS_STATS_TYPE_SPECIAL},
	{"TX_DROPPED_HROOM",		NSS_STATS_TYPE_DROP},
	{"RX_CBUFFER_ALLOC_FAIL",	NSS_STATS_TYPE_SPECIAL},
	{"RX_CENQUEUE_FAIL",		NSS_STATS_TYPE_SPECIAL},
	{"RX_DECRYPT_DONE",		NSS_STATS_TYPE_SPECIAL},
	{"RX_FORWARD_ENQUEUE_FAIL",	NSS_STATS_TYPE_SPECIAL},
	{"TX_CBUFFER_ALLOC_FAIL",	NSS_STATS_TYPE_SPECIAL},
	{"TX_CENQUEUE_FAIL",		NSS_STATS_TYPE_SPECIAL},
	{"TX_DROPPED_TROOM",		NSS_STATS_TYPE_DROP},
	{"TX_FORWARD_ENQUEUE_FAIL",	NSS_STATS_TYPE_SPECIAL},
	{"TX_CIPHER_DONE",		NSS_STATS_TYPE_SPECIAL},
	{"CRYPTO_NOSUPP",		NSS_STATS_TYPE_SPECIAL},
	{"RX_DROPPED_MH_VERSION",	NSS_STATS_TYPE_SPECIAL},
	{"RX_UNALIGNED_PKT",		NSS_STATS_TYPE_SPECIAL}
};

/*
 * nss_gre_tunnel_stats_session_debug_str_strings_read()
 *	Read gre_tunnel session debug statistics names
 */
static ssize_t nss_gre_tunnel_stats_session_debug_str_strings_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return nss_strings_print(ubuf, sz, ppos, nss_gre_tunnel_stats_session_debug_str, NSS_GRE_TUNNEL_STATS_SESSION_MAX);
}

/*
 * nss_gre_tunnel_stats_session_debug_str_strings_ops
 */
NSS_STRINGS_DECLARE_FILE_OPERATIONS(gre_tunnel_stats_session_debug_str);

/*
 * nss_gre_tunnel_strings_dentry_create()
 *	Create gre_tunnel statistics strings debug entry.
 */
void nss_gre_tunnel_strings_dentry_create(void)
{
	nss_strings_create_dentry("gre_tunnel", &nss_gre_tunnel_stats_session_debug_str_strings_ops);
}

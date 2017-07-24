/*
 ******************************************************************************
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
 * ****************************************************************************
 */

#ifndef __NSS_MAP_T_STATS_H
#define __NSS_MAP_T_STATS_H

/*
 * MAP-T debug error types
 */
enum nss_map_t_stats_instance {
	NSS_MAP_T_STATS_V4_TO_V6_PBUF_EXCEPTION,
	NSS_MAP_T_STATS_V4_TO_V6_PBUF_NO_MATCHING_RULE,
	NSS_MAP_T_STATS_V4_TO_V6_PBUF_NOT_TCP_OR_UDP,
	NSS_MAP_T_STATS_V4_TO_V6_RULE_ERR_LOCAL_PSID,
	NSS_MAP_T_STATS_V4_TO_V6_RULE_ERR_LOCAL_IPV6,
	NSS_MAP_T_STATS_V4_TO_V6_RULE_ERR_REMOTE_PSID,
	NSS_MAP_T_STATS_V4_TO_V6_RULE_ERR_REMOTE_EA_BITS,
	NSS_MAP_T_STATS_V4_TO_V6_RULE_ERR_REMOTE_IPV6,
	NSS_MAP_T_STATS_V6_TO_V4_PBUF_EXCEPTION,
	NSS_MAP_T_STATS_V6_TO_V4_PBUF_NO_MATCHING_RULE,
	NSS_MAP_T_STATS_V6_TO_V4_PBUF_NOT_TCP_OR_UDP,
	NSS_MAP_T_STATS_V6_TO_V4_RULE_ERR_LOCAL_IPV4,
	NSS_MAP_T_STATS_V6_TO_V4_RULE_ERR_REMOTE_IPV4,
	NSS_MAP_T_STATS_MAX
};

/*
 * NSS core stats -- for H2N/N2H map_t debug stats
 */
struct nss_map_t_stats_instance_debug {
	uint64_t stats[NSS_MAP_T_STATS_MAX];
	int32_t if_index;
	uint32_t if_num; /* nss interface number */
	bool valid;
};

/*
 * MAP-T statistics APIs
 */
extern void nss_map_t_stats_dentry_create(void);

#endif /* __NSS_MAP_T_STATS_H */

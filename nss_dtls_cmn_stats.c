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

#include "nss_core.h"
#include "nss_dtls_cmn.h"
#include "nss_dtls_cmn_stats.h"
#include "nss_dtls_cmn_strings.h"

#define NSS_DTLS_CMN_INTERFACE_MAX_LONG BITS_TO_LONGS(NSS_MAX_NET_INTERFACES)

extern nss_dtls_cmn_cmn_pvt dtls_cmn_pvt;

/*
 * Declare atomic notifier data structure for statistics.
 */
ATOMIC_NOTIFIER_HEAD(nss_dtls_cmn_stats_notifier);

/*
 * Spinlock to protect dtls common statistics update/read
 */
DEFINE_SPINLOCK(nss_dtls_cmn_stats_lock);

/*
 * nss_dtls_cmn_ctx_stats
 *	dtls common ctx statistics
 */
uint64_t nss_dtls_cmn_ctx_stats[NSS_MAX_NET_INTERFACES][NSS_DTLS_CMN_CTX_STATS_MAX];

/*
 * nss_dtls_cmn_stats_read()
 *	Read dtls common node statiistics.
 */
static ssize_t nss_dtls_cmn_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	/*
	 * Max output lines = #stats +
	 * few blank lines for banner printing + Number of Extra outputlines
	 * for future reference to add new stats
	 */
	uint32_t max_output_lines = NSS_DTLS_CMN_CTX_STATS_MAX + NSS_STATS_EXTRA_OUTPUT_LINES;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	struct nss_ctx_instance *nss_ctx = nss_dtls_cmn_get_context();
	enum nss_dynamic_interface_type type;
	uint64_t *stats_shadow;
	ssize_t bytes_read = 0;
	size_t size_wr = 0;
	uint32_t if_num;
	int32_t i;

	char *lbuf = vzalloc(size_al);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return -ENOMEM;
	}

	stats_shadow = vzalloc(NSS_DTLS_CMN_CTX_STATS_MAX * 8);
	if (unlikely(!stats_shadow)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		vfree(lbuf);
		return -ENOMEM;
	}

	/*
	 * Common node stats for each DTLS dynamic interface.
	 */
	for_each_set_bit(if_num, dtls_cmn_pvt.if_map, NSS_MAX_NET_INTERFACES) {

		type = nss_dynamic_interface_get_type(nss_ctx, if_num);

		switch (type) {
		case NSS_DYNAMIC_INTERFACE_TYPE_DTLS_CMN_INNER:
			/*
			 * dtls common statistics
			 */
			spin_lock_bh(&nss_dtls_cmn_stats_lock);
			for (i = 0; i < NSS_DTLS_CMN_CTX_STATS_MAX; i++)
				stats_shadow[i] = nss_dtls_cmn_ctx_stats[if_num][i];

			spin_unlock_bh(&nss_dtls_cmn_stats_lock);
			size_wr += nss_stats_banner(lbuf, size_wr, size_al, "dtls_cmn inner stats", NSS_STATS_SINGLE_CORE);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nInner if_num:%03u\n", if_num);
			size_wr += nss_stats_print("dtls_cmn", NULL, NSS_STATS_SINGLE_INSTANCE, nss_dtls_cmn_ctx_stats_str,
							stats_shadow, NSS_DTLS_CMN_CTX_STATS_MAX, lbuf, size_wr, size_al);
			break;

		case NSS_DYNAMIC_INTERFACE_TYPE_DTLS_CMN_OUTER:
			/*
			 * dtls common statistics
			 */
			spin_lock_bh(&nss_dtls_cmn_stats_lock);
			for (i = 0; i < NSS_DTLS_CMN_CTX_STATS_MAX; i++)
				stats_shadow[i] = nss_dtls_cmn_ctx_stats[if_num][i];

			spin_unlock_bh(&nss_dtls_cmn_stats_lock);
			size_wr += nss_stats_banner(lbuf, size_wr, size_al, "dtls_cmn outer stats", NSS_STATS_SINGLE_CORE);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nouter if_num:%03u\n", if_num);
			size_wr += nss_stats_print("dtls_cmn", NULL, NSS_STATS_SINGLE_INSTANCE, nss_dtls_cmn_ctx_stats_str,
							stats_shadow, NSS_DTLS_CMN_CTX_STATS_MAX, lbuf, size_wr, size_al);
			break;

		default:
			break;
		}
	}

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	vfree(lbuf);
	vfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_dtls_cmn_stats_ops.
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(dtls_cmn);

/*
 * nss_dtls_cmn_stats_dentry_create()
 *	Create dtls common statistics debug entry.
 */
void nss_dtls_cmn_stats_dentry_create(void)
{
	nss_stats_create_dentry("dtls_cmn", &nss_dtls_cmn_stats_ops);
}

/*
 * nss_dtls_cmn_stats_sync()
 *	Update dtls common node statistics.
 */
void nss_dtls_cmn_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm)
{
	struct nss_dtls_cmn_msg *ndcm = (struct nss_dtls_cmn_msg *)ncm;
	struct nss_dtls_cmn_ctx_stats *ndccs = &ndcm->msg.stats;
	uint64_t *ctx_stats;
	uint32_t *msg_stats;
	uint16_t i = 0;

	spin_lock_bh(&nss_dtls_cmn_stats_lock);

	msg_stats = (uint32_t *)ndccs;
	ctx_stats = nss_dtls_cmn_ctx_stats[ncm->interface];

	for (i = 0; i < NSS_DTLS_CMN_CTX_STATS_MAX; i++, ctx_stats++, msg_stats++)
		*ctx_stats += *msg_stats;

	spin_unlock_bh(&nss_dtls_cmn_stats_lock);
}

/*
 * nss_dtls_cmn_stats_notify()
 *	Sends notifications to all the registered modules.
 *
 * Leverage NSS-FW statistics timing to update Netlink.
 */
void nss_dtls_cmn_stats_notify(struct nss_ctx_instance *nss_ctx)
{
	struct nss_dtls_cmn_stats_notification dtls_cmn_stats;

	dtls_cmn_stats.core_id = nss_ctx->id;
	memcpy(dtls_cmn_stats.stats_ctx, nss_dtls_cmn_ctx_stats, sizeof(dtls_cmn_stats.stats_ctx));
	atomic_notifier_call_chain(&nss_dtls_cmn_stats_notifier, NSS_STATS_EVENT_NOTIFY, &dtls_cmn_stats);
}

/*
 * nss_dtls_cmn_stats_register_notifier()
 *	Registers statistics notifier.
 */
int nss_dtls_cmn_stats_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&nss_dtls_cmn_stats_notifier, nb);
}
EXPORT_SYMBOL(nss_dtls_cmn_stats_register_notifier);

/*
 * nss_dtls_cmn_stats_unregister_notifier()
 *	Deregisters statistics notifier.
 */
int nss_dtls_cmn_stats_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&nss_dtls_cmn_stats_notifier, nb);
}
EXPORT_SYMBOL(nss_dtls_cmn_stats_unregister_notifier);

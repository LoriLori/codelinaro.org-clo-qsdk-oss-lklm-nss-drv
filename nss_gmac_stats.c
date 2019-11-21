/*
 **************************************************************************
 * Copyright (c) 2016-2017, 2019, The Linux Foundation. All rights reserved.
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
#include "nss_gmac_stats.h"

/*
 * nss_gmac_stats_str
 *	GMAC stats strings.
 */
static int8_t *nss_gmac_stats_str[NSS_GMAC_STATS_MAX] = {
	"ticks",
	"worst_ticks",
	"iterations"
};

/*
 * nss_gmac_stats_read()
 *	Read GMAC stats.
 */
ssize_t nss_gmac_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, id;

	/*
	 * max output lines = ((#stats + start tag + one blank) * #GMACs) + start/end tag + 3 blank.
	 */
	uint32_t max_output_lines = ((NSS_GMAC_STATS_MAX + 2) * NSS_MAX_PHYSICAL_INTERFACES) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_GMAC_STATS_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "gmac stats start:\n\n");

	for (id = 0; id < NSS_MAX_PHYSICAL_INTERFACES; id++) {
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_GMAC_STATS_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_gmac[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "GMAC ID: %d\n", id);
		for (i = 0; (i < NSS_GMAC_STATS_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_gmac_stats_str[i], stats_shadow[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngmac stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}


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

/*
 * nss_tstamp.h
 *	NSS to HLOS Tstamp interface definitions.
 */

#ifndef __NSS_TSTAMP_H
#define __NSS_TSTAMP_H

/**
 * @brief Metadata added by the tstamp HLOS driver
 * while sending the packet to NSS tstamp module.
 */
struct nss_tstamp_h2n_pre_hdr {
	uint32_t ts_ifnum;	/* time stamp interface number */
	uint32_t ts_tx_hdr_sz;	/* total header size */
};

/**
 * @brief Metadata added by the NSS tstamp module before sending
 * the packet to host.
 */
struct nss_tstamp_n2h_pre_hdr {
	uint32_t ts_ifnum;	/* time stamp interface number */
	uint32_t ts_data_lo;	/* time stamp lower order bits */
	uint32_t ts_data_hi;	/* time stamp higher order bits */

	uint32_t ts_tx;		/* time stamp direction */
	uint32_t ts_hdr_sz;	/* size of the header including the skb data alignment padding */
};

/**
 * @brief transfer the packet to Tstamp NSS module
 *
 * @return nss_tx_status
 */
nss_tx_status_t nss_tstamp_tx_buf(struct nss_ctx_instance *nss_ctx, struct sk_buff *skb, uint32_t if_num);

#endif /* __NSS_TSTAMP_H */

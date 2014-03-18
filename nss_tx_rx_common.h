/*
 **************************************************************************
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
 * nss_tx_rx_common.h
 *	NSS APIs common header file
 */

#ifndef __NSS_TX_RX_COMMON_H
#define __NSS_TX_RX_COMMON_H

#include "nss_core.h"
#include <nss_hal.h>
#include <linux/module.h>

/*
 * Global definitions
 */
#define NSS_HLOS_MESSAGE_VERSION 1

/*
 * Global variables/extern declarations
 */
extern struct nss_top_instance nss_top_main;

#if (NSS_DEBUG_LEVEL > 0)
#define NSS_VERIFY_CTX_MAGIC(x) nss_verify_ctx_magic(x)
#define NSS_VERIFY_INIT_DONE(x) nss_verify_init_done(x)

/*
 * nss_verify_ctx_magic()
 */
static inline void nss_verify_ctx_magic(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->magic == NSS_CTX_MAGIC);
}

static inline void nss_verify_init_done(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->state == NSS_CORE_STATE_INITIALIZED);
}

#else
#define NSS_VERIFY_CTX_MAGIC(x)
#define NSS_VERIFY_INIT_DONE(x)
#endif

/*
 * CB handlers for variour interfaces
 */
extern void nss_crypto_register_handler(void);
extern void nss_ipsec_register_handler(void);
extern void nss_ipv4_register_handler(void);
extern void nss_ipv6_register_handler(void);
extern void nss_offload_stats_register_handler(void);
extern void nss_phys_if_register_handler(uint32_t if_num);
extern void nss_tun6rd_register_handler(void);
extern void nss_tunipip6_register_handler(void);
extern void nss_pppoe_register_handler(void);

#endif /* __NSS_TX_RX_COMMON_H */

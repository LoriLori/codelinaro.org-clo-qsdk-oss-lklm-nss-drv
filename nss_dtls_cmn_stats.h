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

#ifndef __NSS_DTLS_CMN_STATS_H
#define __NSS_DTLS_CMN_STATS_H

#include <nss_cmn.h>

#define NSS_DTLS_CMN_INTERFACE_MAX_LONG BITS_TO_LONGS(NSS_MAX_NET_INTERFACES)

/*
 * Private data structure.
 */
typedef struct {
	struct semaphore sem;
	struct completion complete;
	enum nss_dtls_cmn_error resp;
	unsigned long if_map[NSS_DTLS_CMN_INTERFACE_MAX_LONG];
} nss_dtls_cmn_cmn_pvt;

/**
 * nss_dtls_cmn_ctx_stats_types
 *	dtls common ctx statistics types
 */
enum nss_dtls_cmn_ctx_stats_types {
	NSS_DTLS_CMN_STATS_RX_SINGLE_REC = NSS_STATS_NODE_MAX,	/**< Received single DTLS record datagrams. */
	NSS_DTLS_CMN_STATS_RX_MULTI_REC,			/**< Received multiple DTLS record datagrams. */
	NSS_DTLS_CMN_STATS_FAIL_CRYPTO_RESOURCE,		/**< Failure in allocation of crypto resource. */
	NSS_DTLS_CMN_STATS_FAIL_CRYPTO_ENQUEUE,			/**< Failure due to queue full in crypto or hardware. */
	NSS_DTLS_CMN_STATS_FAIL_HEADROOM,			/**< Failure in headroom check. */
	NSS_DTLS_CMN_STATS_FAIL_TAILROOM,			/**< Failure in tailroom check. */
	NSS_DTLS_CMN_STATS_FAIL_VER,				/**< Failure in DTLS version check. */
	NSS_DTLS_CMN_STATS_FAIL_EPOCH,				/**< Failure in DTLS epoch check. */
	NSS_DTLS_CMN_STATS_FAIL_DTLS_RECORD,			/**< Failure in reading DTLS record. */
	NSS_DTLS_CMN_STATS_FAIL_CAPWAP,				/**< Failure in CAPWAP classification. */
	NSS_DTLS_CMN_STATS_FAIL_REPLAY,				/**< Failure in anti-replay check. */
	NSS_DTLS_CMN_STATS_FAIL_REPLAY_DUP,			/**< Failure in anti-replay; duplicate records. */
	NSS_DTLS_CMN_STATS_FAIL_REPLAY_WIN,			/**< Failure in anti-replay; packet outside the window. */
	NSS_DTLS_CMN_STATS_FAIL_QUEUE,				/**< Failure due to queue full in DTLS. */
	NSS_DTLS_CMN_STATS_FAIL_QUEUE_NEXTHOP,			/**< Failure due to queue full in next_hop. */
	NSS_DTLS_CMN_STATS_FAIL_PBUF_ALLOC,			/**< Failure in pbuf allocation. */
	NSS_DTLS_CMN_STATS_FAIL_PBUF_LINEAR,			/**< Failure in pbuf linearization. */
	NSS_DTLS_CMN_STATS_FAIL_PBUF_STATS,			/**< Failure in pbuf allocation for statistics. */
	NSS_DTLS_CMN_STATS_FAIL_PBUF_ALIGN,			/**< Failure in pbuf alignment. */
	NSS_DTLS_CMN_STATS_FAIL_CTX_ACTIVE,			/**< Failure in enqueue due to inactive context. */
	NSS_DTLS_CMN_STATS_FAIL_HWCTX_ACTIVE,			/**< Failure in enqueue due to inactive hardware context. */
	NSS_DTLS_CMN_STATS_FAIL_CIPHER,				/**< Failure in decrypting the data. */
	NSS_DTLS_CMN_STATS_FAIL_AUTH,				/**< Failure in authenticating the data. */
	NSS_DTLS_CMN_STATS_FAIL_SEQ_OVF,			/**< Failure due to sequence number overflow. */
	NSS_DTLS_CMN_STATS_FAIL_BLK_LEN,			/**< Failure in decapsulation due to bad cipher block length. */
	NSS_DTLS_CMN_STATS_FAIL_HASH_LEN,			/**< Failure in decapsulation due to bad hash block length. */
	NSS_DTLS_CMN_STATS_LEN_ERROR,				/**< Length error. */
	NSS_DTLS_CMN_STATS_TOKEN_ERROR,				/**< Token error, unknown token command/instruction. */
	NSS_DTLS_CMN_STATS_BYPASS_ERROR,			/**< Token contains too much bypass data. */
	NSS_DTLS_CMN_STATS_CONFIG_ERROR,			/**< Invalid command/algorithm/mode/combination. */
	NSS_DTLS_CMN_STATS_ALGO_ERROR,				/**< Unsupported algorithm. */
	NSS_DTLS_CMN_STATS_HASH_OVF_ERROR,			/**< Hash input overflow. */
	NSS_DTLS_CMN_STATS_TTL_ERROR,				/**< TTL or HOP-Limit underflow. */
	NSS_DTLS_CMN_STATS_CSUM_ERROR,				/**< Checksum error. */
	NSS_DTLS_CMN_STATS_TIMEOUT_ERROR,			/**< Data timed-out. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_0,				/**< Classification failure 0. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_1,				/**< Classification failure 1. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_2,				/**< Classification failure 2. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_3,				/**< Classification failure 3. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_4,				/**< Classification failure 4. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_5,				/**< Classification failure 5. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_6,				/**< Classification failure 6. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_7,				/**< Classification failure 7. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_8,				/**< Classification failure 8. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_9,				/**< Classification failure 9. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_10,			/**< Classification failure 10. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_11,			/**< Classification failure 11. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_12,			/**< Classification failure 12. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_13,			/**< Classification failure 13. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_14,			/**< Classification failure 14. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_15,			/**< Classification failure 15. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_16,			/**< Classification failure 16. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_17,			/**< Classification failure 17. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_18,			/**< Classification failure 18. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_19,			/**< Classification failure 19. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_20,			/**< Classification failure 20. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_21,			/**< Classification failure 21. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_22,			/**< Classification failure 22. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_23,			/**< Classification failure 23. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_24,			/**< Classification failure 24. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_25,			/**< Classification failure 25. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_26,			/**< Classification failure 26. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_27,			/**< Classification failure 27. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_28,			/**< Classification failure 28. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_29,			/**< Classification failure 29. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_30,			/**< Classification failure 30. */
	NSS_DTLS_CMN_STATS_CLE_ERROR_31,			/**< Classification failure 31. */
	NSS_DTLS_CMN_STATS_SEQ_LOW,				/**< Lower 32 bits of current Tx sequence number. */
	NSS_DTLS_CMN_STATS_SEQ_HIGH,				/**< Upper 16 bits of current Tx sequence number. */
	NSS_DTLS_CMN_STATS_EPOCH,				/**< Current epoch value. */
	NSS_DTLS_CMN_CTX_STATS_MAX,				/**< maximum message type. */
};

/**
 * nss_dtls_cmn_stats_notification
 *	dtls common transmission statistics structure
 */
struct nss_dtls_cmn_stats_notification {
	uint32_t core_id;				/* core ID */
	uint64_t stats_ctx[NSS_DTLS_CMN_CTX_STATS_MAX];	/* CTX transmission statistics */
};

extern void nss_dtls_cmn_stats_notify(struct nss_ctx_instance *nss_ctx);
extern void nss_dtls_cmn_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm);
extern void nss_dtls_cmn_stats_dentry_create(void);

/**
 * nss_dtls_cmn_stats_register_notifier
 *	Registers a statistics notifier.
 *
 * @datatypes
 *	notifier_block
 *
 * @param[in] nb Notifier block.
 *
 * @return
 * 0 on success or -2 on failure.
 */
extern int nss_dtls_cmn_stats_register_notifier(struct notifier_block *nb);

/**
 * nss_dtls_cmn_stats_unregister_notifier
 *	Deregisters a statistics notifier.
 *
 * @datatypes
 *	notifier_block
 *
 * @param[in] nb Notifier block.
 *
 * @return
 * 0 on success or -2 on failure.
 */
extern int nss_dtls_cmn_stats_unregister_notifier(struct notifier_block *nb);

#endif /* __NSS_DTLS_CMN_STATS_H */

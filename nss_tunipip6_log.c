/*
 **************************************************************************
 * Copyright (c) 2018, 2020, The Linux Foundation. All rights reserved.
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
 * nss_tunipip6_log.c
 *	NSS TUNIPIP6 logger file.
 */

#include "nss_core.h"

/*
 * nss_tunipip6_log_message_types_str
 *	NSS TUNIPIP6 message strings
 */
static int8_t *nss_tunipip6_log_message_types_str[NSS_TUNIPIP6_MAX] __maybe_unused = {
	"TUNIPIP6 Interface Create",
	"TUNIPIP6 Stats",
	"TUNIPIP6 FMR rules"
};

/*
 * nss_tunipip6_log_fmr_rule()
 *	Log NSS TUNIPIP6 FMR rule.
 */
static void nss_tunipip6_log_fmr_rule(struct nss_tunipip6_msg *ntm)
{
	struct nss_tunipip6_fmr *nfmr __maybe_unused = &ntm->msg.fmr_rule;
	nss_trace("%px: NSS TUNIPIP6 Interface Create message \n"
		"TUNIPIP6 FMR IPv6 prefix: %pI6\n"
		"TUNIPIP6 FMR IPv6 prefix length: %d\n"
		"TUNIPIP6 FMR IPv4 prefix: %pI4\n"
		"TUNIPIP6 FMR IPv4 prefix length: %d\n"
		"TUNIPIP6 FMR IPv6 suffix: %pI6\n"
		"TUNIPIP6 FMR IPv6 suffix length: %d\n"
		"TUNIPIP6 FMR EA length: %d\n"
		"TUNIPIP6 FMR PSID offset: %d\n",
		nfmr, nfmr->ip6_prefix,
		nfmr->ip6_prefix_len,&nfmr->ip4_prefix,
		nfmr->ip4_prefix_len, nfmr->ip6_suffix,
		nfmr->ip6_suffix_len, nfmr->ea_len,
		nfmr->psid_offset);
}

/*
 * nss_tunipip6_log_if_create_msg()
 *	Log NSS TUNIPIP6 Interface Create
 */
static void nss_tunipip6_log_if_create_msg(struct nss_tunipip6_msg *ntm)
{
	struct nss_tunipip6_create_msg *ntcm __maybe_unused = &ntm->msg.tunipip6_create;
	nss_trace("%px: NSS TUNIPIP6 Interface Create message \n"
		"TUNIPIP6 Source Address: %pI6\n"
		"TUNIPIP6 Destination Address: %pI6\n"
		"TUNIPIP6 Flow Label: %d\n"
		"TUNIPIP6 Flags: %d\n"
		"TUNIPIP6 Hop Limit: %d\n"
		"TUNIPIP6 Draft03 Specification: %d\n"
		"TUNIPIP6 TTL inherit: %s\n"
		"TUNIPIP6 TOS inherit: %s\n",
		ntcm, ntcm->saddr,
		ntcm->daddr, ntcm->flowlabel,
		ntcm->flags, ntcm->hop_limit,
		ntcm->draft03,
		ntcm->ttl_inherit ? "true":"flase",
		ntcm->tos_inherit ? "true":"flase");
}

/*
 * nss_tunipip6_log_verbose()
 *	Log message contents.
 */
static void nss_tunipip6_log_verbose(struct nss_tunipip6_msg *ntm)
{
	switch (ntm->cm.type) {
	case NSS_TUNIPIP6_TX_ENCAP_IF_CREATE:
	case NSS_TUNIPIP6_TX_DECAP_IF_CREATE:
		nss_tunipip6_log_if_create_msg(ntm);
		break;

	case NSS_TUNIPIP6_RX_STATS_SYNC:
		/*
		 * No log for valid stats message.
		 */
		break;

	case NSS_TUNIPIP6_FMR_RULE_ADD:
	case NSS_TUNIPIP6_FMR_RULE_DEL:
		nss_tunipip6_log_fmr_rule(ntm);
		break;

	default:
		nss_trace("%px: Invalid message type\n", ntm);
		break;
	}
}

/*
 * nss_tunipip6_log_tx_msg()
 *	Log messages transmitted to FW.
 */
void nss_tunipip6_log_tx_msg(struct nss_tunipip6_msg *ntm)
{
	if (ntm->cm.type >= NSS_TUNIPIP6_MAX) {
		nss_warning("%px: Invalid message type\n", ntm);
		return;
	}

	nss_info("%px: type[%d]:%s\n", ntm, ntm->cm.type, nss_tunipip6_log_message_types_str[ntm->cm.type]);
	nss_tunipip6_log_verbose(ntm);
}

/*
 * nss_tunipip6_log_rx_msg()
 *	Log messages received from FW.
 */
void nss_tunipip6_log_rx_msg(struct nss_tunipip6_msg *ntm)
{
	if (ntm->cm.response >= NSS_CMN_RESPONSE_LAST) {
		nss_warning("%px: Invalid response\n", ntm);
		return;
	}

	if (ntm->cm.response == NSS_CMN_RESPONSE_NOTIFY || (ntm->cm.response == NSS_CMN_RESPONSE_ACK)) {
		nss_info("%px: type[%d]:%s, response[%d]:%s\n", ntm, ntm->cm.type,
			nss_tunipip6_log_message_types_str[ntm->cm.type],
			ntm->cm.response, nss_cmn_response_str[ntm->cm.response]);
		goto verbose;
	}

	nss_info("%px: msg nack - type[%d]:%s, response[%d]:%s\n",
		ntm, ntm->cm.type, nss_tunipip6_log_message_types_str[ntm->cm.type],
		ntm->cm.response, nss_cmn_response_str[ntm->cm.response]);

verbose:
	nss_tunipip6_log_verbose(ntm);
}

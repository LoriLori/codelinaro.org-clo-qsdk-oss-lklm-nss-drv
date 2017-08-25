/*
 **************************************************************************
 * Copyright (c) 2013-2017, The Linux Foundation. All rights reserved.
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
 * nss_stats.c
 *	NSS stats APIs
 *
 */

#include "nss_core.h"
#include "nss_dtls_stats.h"
#include "nss_gre_tunnel_stats.h"

/*
 * Maximum string length:
 * This should be equal to maximum string size of any stats
 * inclusive of stats value
 */
#define NSS_STATS_MAX_STR_LENGTH 96
#define NSS_STATS_WIFILI_MAX	(NSS_STATS_WIFILI_TXRX_MAX + NSS_STATS_WIFILI_TCL_MAX + \
				NSS_STATS_WIFILI_TX_DESC_FREE_MAX + NSS_STATS_WIFILI_REO_MAX + \
				NSS_STATS_WIFILI_TX_DESC_MAX + NSS_STATS_WIFILI_EXT_TX_DESC_MAX + \
				NSS_STATS_WIFILI_RX_DESC_MAX + NSS_STATS_WIFILI_RXDMA_DESC_MAX)

extern int32_t nss_tx_rx_virt_if_copy_stats(int32_t if_num, int i, char *line);

uint64_t stats_shadow_pppoe_except[NSS_PPPOE_NUM_SESSION_PER_INTERFACE][NSS_PPPOE_EXCEPTION_EVENT_MAX];

/*
 * Private data for every file descriptor
 */
struct nss_stats_data {
	uint32_t if_num;	/* Interface number for stats */
	uint32_t index;		/* Index for GRE_REDIR stats */
	uint32_t edma_id;	/* EDMA port ID or ring ID */
	struct nss_ctx_instance *nss_ctx;
				/* The core for project stats */
};

/*
 * Statistics structures
 */

/*
 * nss_stats_str_ipv4
 *	IPv4 stats strings
 */
static int8_t *nss_stats_str_ipv4[NSS_STATS_IPV4_MAX] = {
	"rx_pkts",
	"rx_bytes",
	"tx_pkts",
	"tx_bytes",
	"create_requests",
	"create_collisions",
	"create_invalid_interface",
	"destroy_requests",
	"destroy_misses",
	"hash_hits",
	"hash_reorders",
	"flushes",
	"evictions",
	"fragmentations",
	"dropped_by_rule",
	"mc_create_requests",
	"mc_update_requests",
	"mc_create_invalid_interface",
	"mc_destroy_requests",
	"mc_destroy_misses",
	"mc_flushes",
};

/*
 * nss_stats_str_ipv4_reasm
 *	IPv4 reassembly stats strings
 */
static int8_t *nss_stats_str_ipv4_reasm[NSS_STATS_IPV4_REASM_MAX] = {
	"evictions",
	"alloc_fails",
	"timeouts",
};

/*
 * nss_stats_str_ipv6
 *	IPv6 stats strings
 */
static int8_t *nss_stats_str_ipv6[NSS_STATS_IPV6_MAX] = {
	"rx_pkts",
	"rx_bytes",
	"tx_pkts",
	"tx_bytes",
	"create_requests",
	"create_collisions",
	"create_invalid_interface",
	"destroy_requests",
	"destroy_misses",
	"hash_hits",
	"hash_reorders",
	"flushes",
	"evictions",
	"fragmentations",
	"frag_fails",
	"dropped_by_rule",
	"mc_create_requests",
	"mc_update_requests",
	"mc_create_invalid_interface",
	"mc_destroy_requests",
	"mc_destroy_misses",
	"mc_flushes",
};

/*
 * nss_stats_str_ipv6_reasm
 *	IPv6 reassembly stats strings
 */
static int8_t *nss_stats_str_ipv6_reasm[NSS_STATS_IPV6_REASM_MAX] = {
	"alloc_fails",
	"timeouts",
	"discards",
};

/*
 * nss_stats_str_n2h
 *	N2H stats strings
 */
static int8_t *nss_stats_str_n2h[NSS_STATS_N2H_MAX] = {
	"queue_dropped",
	"ticks",
	"worst_ticks",
	"iterations",
	"pbuf_ocm_alloc_fails",
	"pbuf_ocm_free_count",
	"pbuf_ocm_total_count",
	"pbuf_default_alloc_fails",
	"pbuf_default_free_count",
	"pbuf_default_total_count",
	"payload_fails",
	"payload_free_count",
	"h2n_control_packets",
	"h2n_control_bytes",
	"n2h_control_packets",
	"n2h_control_bytes",
	"h2n_data_packets",
	"h2n_data_bytes",
	"n2h_data_packets",
	"n2h_data_bytes",
	"n2h_tot_payloads",
	"n2h_data_interface_invalid",
};

/*
 * nss_stats_str_lso_rx
 *	LSO_RX stats strings
 */
static int8_t *nss_stats_str_lso_rx[NSS_STATS_LSO_RX_MAX] = {
	"tx_dropped",
	"dropped",
	"pbuf_alloc_fail",
	"pbuf_reference_fail"
};

/*
 * nss_stats_str_drv
 *	Host driver stats strings
 */
static int8_t *nss_stats_str_drv[NSS_STATS_DRV_MAX] = {
	"nbuf_alloc_errors",
	"paged_buf_alloc_errors",
	"tx_queue_full[0]",
	"tx_queue_full[1]",
	"tx_buffers_empty",
	"tx_paged_buffers_empty",
	"tx_buffers_pkt",
	"tx_buffers_cmd",
	"tx_buffers_crypto",
	"tx_buffers_reuse",
	"rx_buffers_empty",
	"rx_buffers_pkt",
	"rx_buffers_cmd_resp",
	"rx_buffers_status_sync",
	"rx_buffers_crypto",
	"rx_buffers_virtual",
	"tx_skb_simple",
	"tx_skb_nr_frags",
	"tx_skb_fraglist",
	"rx_skb_simple",
	"rx_skb_nr_frags",
	"rx_skb_fraglist",
	"rx_bad_desciptor",
	"nss_skb_count",
	"rx_chain_seg_processed",
	"rx_frag_seg_processed"
};

/*
 * nss_stats_str_pppoe
 *	PPPoE stats strings
 */
static int8_t *nss_stats_str_pppoe[NSS_STATS_PPPOE_MAX] = {
	"create_requests",
	"create_failures",
	"destroy_requests",
	"destroy_misses"
};

/*
 * nss_stats_str_gmac
 *	GMAC stats strings
 */
static int8_t *nss_stats_str_gmac[NSS_STATS_GMAC_MAX] = {
	"ticks",
	"worst_ticks",
	"iterations"
};

/*
 * nss_stats_str_edma_tx
 */
static int8_t *nss_stats_str_edma_tx[NSS_STATS_EDMA_TX_MAX] = {
	"tx_err",
	"tx_dropped",
	"desc_cnt"
};

/*
 * nss_stats_str_edma_rx
 */
static int8_t *nss_stats_str_edma_rx[NSS_STATS_EDMA_RX_MAX] = {
	"rx_csum_err",
	"desc_cnt",
	"qos_err"
};

/*
 * nss_stats_str_edma_txcmpl
 */
static int8_t *nss_stats_str_edma_txcmpl[NSS_STATS_EDMA_TXCMPL_MAX] = {
	"desc_cnt"
};

/*
 * nss_stats_str_edma_rxfill
 */
static int8_t *nss_stats_str_edma_rxfill[NSS_STATS_EDMA_RXFILL_MAX] = {
	"desc_cnt"
};

/*
 * nss_stats_str_edma_port_type
 */
static int8_t *nss_stats_str_edma_port_type[NSS_EDMA_PORT_TYPE_MAX] = {
	"physical_port",
	"virtual_port"
};

/*
 * nss_stats_str_edma_port_ring_map
 */
static int8_t *nss_stats_str_edma_port_ring_map[NSS_EDMA_PORT_RING_MAP_MAX] = {
	"rx_ring",
	"tx_ring"
};

/*
 * nss_stats_str_edma_err_map
 */
static int8_t *nss_stats_str_edma_err_map[NSS_EDMA_ERR_STATS_MAX] = {
	"axi_rd_err",
	"axi_wr_err",
	"rx_desc_fifo_full_err",
	"rx_buf_size_err",
	"tx_sram_full_err",
	"tx_cmpl_buf_full_err",
	"pkt_len_la64k_err",
	"pkt_len_le33_err",
	"data_len_err",
	"alloc_fail_cnt"
};

/*
 * nss_stats_str_node
 *	Interface stats strings per node
 */
static int8_t *nss_stats_str_node[NSS_STATS_NODE_MAX] = {
	"rx_packets",
	"rx_bytes",
	"rx_dropped",
	"tx_packets",
	"tx_bytes"
};

/*
 * nss_stats_str_eth_rx
 *	eth_rx stats strings
 */
static int8_t *nss_stats_str_eth_rx[NSS_STATS_ETH_RX_MAX] = {
	"ticks",
	"worst_ticks",
	"iterations"
};

/*
 * nss_stats_str_if_exception_unknown
 *	Interface stats strings for unknown exceptions
 */
static int8_t *nss_stats_str_if_exception_eth_rx[NSS_EXCEPTION_EVENT_ETH_RX_MAX] = {
	"UNKNOWN_L3_PROTOCOL",
	"ETH_HDR_MISSING",
	"VLAN_MISSING",
	"TRUSTSEC_HDR_MISSING"
};

/*
 * nss_stats_str_if_exception_ipv4
 *	Interface stats strings for ipv4 exceptions
 */
static int8_t *nss_stats_str_if_exception_ipv4[NSS_EXCEPTION_EVENT_IPV4_MAX] = {
	"IPV4_ICMP_HEADER_INCOMPLETE",
	"IPV4_ICMP_UNHANDLED_TYPE",
	"IPV4_ICMP_IPV4_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_UDP_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_TCP_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_UNKNOWN_PROTOCOL",
	"IPV4_ICMP_NO_ICME",
	"IPV4_ICMP_FLUSH_TO_HOST",
	"IPV4_TCP_HEADER_INCOMPLETE",
	"IPV4_TCP_NO_ICME",
	"IPV4_TCP_IP_OPTION",
	"IPV4_TCP_IP_FRAGMENT",
	"IPV4_TCP_SMALL_TTL",
	"IPV4_TCP_NEEDS_FRAGMENTATION",
	"IPV4_TCP_FLAGS",
	"IPV4_TCP_SEQ_EXCEEDS_RIGHT_EDGE",
	"IPV4_TCP_SMALL_DATA_OFFS",
	"IPV4_TCP_BAD_SACK",
	"IPV4_TCP_BIG_DATA_OFFS",
	"IPV4_TCP_SEQ_BEFORE_LEFT_EDGE",
	"IPV4_TCP_ACK_EXCEEDS_RIGHT_EDGE",
	"IPV4_TCP_ACK_BEFORE_LEFT_EDGE",
	"IPV4_UDP_HEADER_INCOMPLETE",
	"IPV4_UDP_NO_ICME",
	"IPV4_UDP_IP_OPTION",
	"IPV4_UDP_IP_FRAGMENT",
	"IPV4_UDP_SMALL_TTL",
	"IPV4_UDP_NEEDS_FRAGMENTATION",
	"IPV4_WRONG_TARGET_MAC",
	"IPV4_HEADER_INCOMPLETE",
	"IPV4_BAD_TOTAL_LENGTH",
	"IPV4_BAD_CHECKSUM",
	"IPV4_NON_INITIAL_FRAGMENT",
	"IPV4_DATAGRAM_INCOMPLETE",
	"IPV4_OPTIONS_INCOMPLETE",
	"IPV4_UNKNOWN_PROTOCOL",
	"IPV4_ESP_HEADER_INCOMPLETE",
	"IPV4_ESP_NO_ICME",
	"IPV4_ESP_IP_OPTION",
	"IPV4_ESP_IP_FRAGMENT",
	"IPV4_ESP_SMALL_TTL",
	"IPV4_ESP_NEEDS_FRAGMENTATION",
	"IPV4_INGRESS_VID_MISMATCH",
	"IPV4_INGRESS_VID_MISSING",
	"IPV4_6RD_NO_ICME",
	"IPV4_6RD_IP_OPTION",
	"IPV4_6RD_IP_FRAGMENT",
	"IPV4_6RD_NEEDS_FRAGMENTATION",
	"IPV4_DSCP_MARKING_MISMATCH",
	"IPV4_VLAN_MARKING_MISMATCH",
	"IPV4_DEPRECATED",
	"IPV4_GRE_HEADER_INCOMPLETE",
	"IPV4_GRE_NO_ICME",
	"IPV4_GRE_IP_OPTION",
	"IPV4_GRE_IP_FRAGMENT",
	"IPV4_GRE_SMALL_TTL",
	"IPV4_GRE_NEEDS_FRAGMENTATION",
	"IPV4_PPTP_GRE_SESSION_MATCH_FAIL",
	"IPV4_PPTP_GRE_INVALID_PROTO",
	"IPV4_PPTP_GRE_NO_CME",
	"IPV4_PPTP_GRE_IP_OPTION",
	"IPV4_PPTP_GRE_IP_FRAGMENT",
	"IPV4_PPTP_GRE_SMALL_TTL",
	"IPV4_PPTP_GRE_NEEDS_FRAGMENTATION",
	"IPV4_DESTROY",
	"IPV4_FRAG_DF_SET",
	"IPV4_FRAG_FAIL",
	"IPV4_ICMP_IPV4_UDPLITE_HEADER_INCOMPLETE",
	"IPV4_UDPLITE_HEADER_INCOMPLETE",
	"IPV4_UDPLITE_NO_ICME",
	"IPV4_UDPLITE_IP_OPTION",
	"IPV4_UDPLITE_IP_FRAGMENT",
	"IPV4_UDPLITE_SMALL_TTL",
	"IPV4_UDPLITE_NEEDS_FRAGMENTATION",
	"IPV4_MC_UDP_NO_ICME",
	"IPV4_MC_MEM_ALLOC_FAILURE",
	"IPV4_MC_UPDATE_FAILURE",
	"IPV4_MC_PBUF_ALLOC_FAILURE"
};

/*
 * nss_stats_str_if_exception_ipv6
 *	Interface stats strings for ipv6 exceptions
 */
static int8_t *nss_stats_str_if_exception_ipv6[NSS_EXCEPTION_EVENT_IPV6_MAX] = {
	"IPV6_ICMP_HEADER_INCOMPLETE",
	"IPV6_ICMP_UNHANDLED_TYPE",
	"IPV6_ICMP_IPV6_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_UDP_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_TCP_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_UNKNOWN_PROTOCOL",
	"IPV6_ICMP_NO_ICME",
	"IPV6_ICMP_FLUSH_TO_HOST",
	"IPV6_TCP_HEADER_INCOMPLETE",
	"IPV6_TCP_NO_ICME",
	"IPV6_TCP_SMALL_HOP_LIMIT",
	"IPV6_TCP_NEEDS_FRAGMENTATION",
	"IPV6_TCP_FLAGS",
	"IPV6_TCP_SEQ_EXCEEDS_RIGHT_EDGE",
	"IPV6_TCP_SMALL_DATA_OFFS",
	"IPV6_TCP_BAD_SACK",
	"IPV6_TCP_BIG_DATA_OFFS",
	"IPV6_TCP_SEQ_BEFORE_LEFT_EDGE",
	"IPV6_TCP_ACK_EXCEEDS_RIGHT_EDGE",
	"IPV6_TCP_ACK_BEFORE_LEFT_EDGE",
	"IPV6_UDP_HEADER_INCOMPLETE",
	"IPV6_UDP_NO_ICME",
	"IPV6_UDP_SMALL_HOP_LIMIT",
	"IPV6_UDP_NEEDS_FRAGMENTATION",
	"IPV6_WRONG_TARGET_MAC",
	"IPV6_HEADER_INCOMPLETE",
	"IPV6_UNKNOWN_PROTOCOL",
	"IPV6_INGRESS_VID_MISMATCH",
	"IPV6_INGRESS_VID_MISSING",
	"IPV6_DSCP_MARKING_MISMATCH",
	"IPV6_VLAN_MARKING_MISMATCH",
	"IPV6_DEPRECATED",
	"IPV6_GRE_NO_ICME",
	"IPV6_GRE_NEEDS_FRAGMENTATION",
	"IPV6_GRE_SMALL_HOP_LIMIT",
	"IPV6_DESTROY",
	"IPV6_ICMP_IPV6_UDPLITE_HEADER_INCOMPLETE",
	"IPV6_UDPLITE_HEADER_INCOMPLETE",
	"IPV6_UDPLITE_NO_ICME",
	"IPV6_UDPLITE_SMALL_HOP_LIMIT",
	"IPV6_UDPLITE_NEEDS_FRAGMENTATION",
	"IPV6_MC_UDP_NO_ICME",
	"IPV6_MC_MEM_ALLOC_FAILURE",
	"IPV6_MC_UPDATE_FAILURE",
	"IPV6_MC_PBUF_ALLOC_FAILURE",
	"IPV6_ESP_HEADER_INCOMPLETE",
	"IPV6_ESP_NO_ICME",
	"IPV6_ESP_IP_FRAGMENT",
	"IPV6_ESP_SMALL_HOP_LIMIT",
	"IPV6_ESP_NEEDS_FRAGMENTATION"
};

/*
 * nss_stats_str_if_exception_pppoe
 *	Interface stats strings for PPPoE exceptions
 */
static int8_t *nss_stats_str_if_exception_pppoe[NSS_PPPOE_EXCEPTION_EVENT_MAX] = {
	"PPPOE_WRONG_VERSION_OR_TYPE",
	"PPPOE_WRONG_CODE",
	"PPPOE_HEADER_INCOMPLETE",
	"PPPOE_UNSUPPORTED_PPP_PROTOCOL",
	"PPPOE_DEPRECATED"
};

/*
 * nss_stats_str_wifi
 *	Wifi statistics strings
 */
static int8_t *nss_stats_str_wifi[NSS_STATS_WIFI_MAX] = {
	"RX_PACKETS",
	"RX_DROPPED",
	"TX_PACKETS",
	"TX_DROPPED",
	"TX_TRANSMIT_COMPLETED",
	"TX_MGMT_RECEIVED",
	"TX_MGMT_TRANSMITTED",
	"TX_MGMT_DROPPED",
	"TX_MGMT_COMPLETED",
	"TX_INV_PEER_ENQ_CNT",
	"RX_INV_PEER_RCV_CNT",
	"RX_PN_CHECK_FAILED",
	"RX_PKTS_DELIVERD",
	"RX_BYTES_DELIVERED",
	"TX_BYTES_COMPLETED",
	"RX_DELIVER_UNALIGNED_DROP_CNT",
	"TIDQ_ENQUEUE_CNT_0",
	"TIDQ_ENQUEUE_CNT_1",
	"TIDQ_ENQUEUE_CNT_2",
	"TIDQ_ENQUEUE_CNT_3",
	"TIDQ_ENQUEUE_CNT_4",
	"TIDQ_ENQUEUE_CNT_5",
	"TIDQ_ENQUEUE_CNT_6",
	"TIDQ_ENQUEUE_CNT_7",
	"TIDQ_DEQUEUE_CNT_0",
	"TIDQ_DEQUEUE_CNT_1",
	"TIDQ_DEQUEUE_CNT_2",
	"TIDQ_DEQUEUE_CNT_3",
	"TIDQ_DEQUEUE_CNT_4",
	"TIDQ_DEQUEUE_CNT_5",
	"TIDQ_DEQUEUE_CNT_6",
	"TIDQ_DEQUEUE_CNT_7",
	"TIDQ_ENQUEUE_FAIL_CNT_0",
	"TIDQ_ENQUEUE_FAIL_CNT_1",
	"TIDQ_ENQUEUE_FAIL_CNT_2",
	"TIDQ_ENQUEUE_FAIL_CNT_3",
	"TIDQ_ENQUEUE_FAIL_CNT_4",
	"TIDQ_ENQUEUE_FAIL_CNT_5",
	"TIDQ_ENQUEUE_FAIL_CNT_6",
	"TIDQ_ENQUEUE_FAIL_CNT_7",
	"TIDQ_TTL_EXPIRE_CNT_0",
	"TIDQ_TTL_EXPIRE_CNT_1",
	"TIDQ_TTL_EXPIRE_CNT_2",
	"TIDQ_TTL_EXPIRE_CNT_3",
	"TIDQ_TTL_EXPIRE_CNT_4",
	"TIDQ_TTL_EXPIRE_CNT_5",
	"TIDQ_TTL_EXPIRE_CNT_6",
	"TIDQ_TTL_EXPIRE_CNT_7",
	"TIDQ_DEQUEUE_REQ_CNT_0",
	"TIDQ_DEQUEUE_REQ_CNT_1",
	"TIDQ_DEQUEUE_REQ_CNT_2",
	"TIDQ_DEQUEUE_REQ_CNT_3",
	"TIDQ_DEQUEUE_REQ_CNT_4",
	"TIDQ_DEQUEUE_REQ_CNT_5",
	"TIDQ_DEQUEUE_REQ_CNT_6",
	"TIDQ_DEQUEUE_REQ_CNT_7",
	"TOTAL_TIDQ_DEPTH",
	"RX_HTT_FETCH_CNT",
	"TOTAL_TIDQ_BYPASS_CNT",
	"GLOBAL_Q_FULL_CNT",
	"TIDQ_FULL_CNT",
};

/*
 * nss_stats_str_wifili
 *	wifili txrx statistics
 */
static int8_t *nss_stats_str_wifili_txrx[NSS_STATS_WIFILI_TXRX_MAX] = {
	"WIFILI_RX_MSDU_ERROR",
	"WIFILI_RX_INV_PEER_RCV",
	"WIFILI_RX_WDS_SRCPORT_EXCEPTION",
	"WIFILI_RX_WDS_SRCPORT_EXCEPTION_FAIL",
	"WIFILI_RX_DELIVERD",
	"WIFILI_RX_DELIVER_DROPPED",
	"WIFILI_RX_INTRA_BSS_UCAST",
	"WIFILI_RX_INTRA_BSS_UCAST_FAIL",
	"WIFILI_RX_INTRA_BSS_MCAST",
	"WIFILI_RX_INTRA_BSS_MCAST_FAIL",
	"WIFILI_RX_SG_RCV_SEND",
	"WIFILI_RX_SG_RCV_FAIL",
	"WIFILI_RX_MCAST_ECHO",
	"WIFILI_TX_ENQUEUE",
	"WIFILI_TX_ENQUEUE_DROP",
	"WIFILI_TX_DEQUEUE",
	"WIFILI_TX_HW_ENQUEUE_FAIL",
	"WIFILI_TX_SENT_COUNT",
};

/*
 * nss_stats_str_wifili_tcl
 *	wifili tcl stats
 */
static int8_t *nss_stats_str_wifili_tcl[NSS_STATS_WIFILI_TCL_MAX] = {
	"WIFILI_TCL_NO_HW_DESC",
	"WIFILI_TCL_RING_FULL",
	"WIFILI_TCL_RING_SENT",
};

/*
 * nss_stats_str_wifili_tx_comp
 *	wifili tx comp stats
 */
static int8_t *nss_stats_str_wifili_tx_comp[NSS_STATS_WIFILI_TX_DESC_FREE_MAX] = {
	"WIFILI_TX_DESC_FREE_INV_BUFSRC",
	"WIFILI_TX_DESC_FREE_INV_COOKIE",
	"WIFILI_TX_DESC_FREE_HW_RING_EMPTY",
	"WIFILI_TX_DESC_FREE_REAPED",
};

/*
 * nss_stats_str_wifili_reo
 *	wifili tx reo stats
 */
static int8_t *nss_stats_str_wifili_reo[NSS_STATS_WIFILI_REO_MAX] = {
	"WIFILI_REO_ERROR",
	"WIFILI_REO_REAPED",
	"WIFILI_REO_INV_COOKIE",
};

/*
 * nss_stats_str_wifili_txsw_pool
 *	wifili tx desc stats
 */
static int8_t *nss_stats_str_wifili_txsw_pool[NSS_STATS_WIFILI_TX_DESC_MAX] = {
	"WIFILI_TX_DESC_IN_USE",
	"WIFILI_TX_DESC_ALLOC_FAIL",
	"WIFILI_TX_DESC_ALREADY_ALLOCATED",
	"WIFILI_TX_DESC_INVALID_FREE",
	"WIFILI_TX_DESC_FREE_SRC_FW",
	"WIFILI_TX_DESC_FREE_COMPLETION",
	"WIFILI_TX_DESC_NO_PB",
};

/*
 * nss_stats_str_wifili_ext_txsw_pool
 *	wifili tx ext desc stats
 */
static uint8_t *nss_stats_str_wifili_ext_txsw_pool[NSS_STATS_WIFILI_EXT_TX_DESC_MAX] = {
	"WIFILI_EXT_TX_DESC_IN_USE",
	"WIFILI_EXT_TX_DESC_ALLOC_FAIL",
	"WIFILI_EXT_TX_DESC_ALREADY_ALLOCATED",
	"WIFILI_EXT_TX_DESC_INVALID_FREE",
};

/*
 * nss_stats_str_wifili_rxdma_pool
 *	wifili rx desc stats
 */
static int8_t *nss_stats_str_wifili_rxdma_pool[NSS_STATS_WIFILI_RX_DESC_MAX] = {
	"WIFILI_RX_DESC_NO_PB",
	"WIFILI_RX_DESC_ALLOC_FAIL",
	"WIFILI_RX_DESC_IN_USE",
};

/*
 * nss_stats_str_wifili_rxdma_ring
 *	wifili rx dma ring stats
 */
static int8_t *nss_stats_str_wifili_rxdma_ring[NSS_STATS_WIFILI_RXDMA_DESC_MAX] = {
	"WIFILI_RXDMA_HW_DESC_UNAVAILABLE",
	"WIFILI_RXDMA_BUF_REPLENISHED",
};

/*
 * nss_stats_str_wifili_wbm
 *	wifili wbm ring stats
 */
static int8_t *nss_stats_str_wifili_wbm[NSS_STATS_WIFILI_WBM_MAX] = {
	"WIFILI_WBM_SRC_DMA",
	"WIFILI_WBM_SRC_DMA_CODE_INV",
	"WIFILI_WBM_SRC_REO",
	"WIFILI_WBM_SRC_REO_CODE_NULLQ",
	"WIFILI_WBM_SRC_REO_CODE_INV",
	"WIFILI_WBM_SRC_INV",
};

/*
 * nss_stats_str_portid
 *	PortID statistics strings
 */
static int8_t *nss_stats_str_portid[NSS_STATS_PORTID_MAX] = {
	"RX_INVALID_HEADER",
};

/*
 * nss_stats_str_dtls_session_stats
 *	DTLS statistics strings for nss session stats
 */
static int8_t *nss_stats_str_dtls_session_debug_stats[NSS_STATS_DTLS_SESSION_MAX] = {
	"RX_PKTS",
	"TX_PKTS",
	"RX_DROPPED",
	"RX_AUTH_DONE",
	"TX_AUTH_DONE",
	"RX_CIPHER_DONE",
	"TX_CIPHER_DONE",
	"RX_CBUF_ALLOC_FAIL",
	"TX_CBUF_ALLOC_FAIL",
	"TX_CENQUEUE_FAIL",
	"RX_CENQUEUE_FAIL",
	"TX_DROPPED_HROOM",
	"TX_DROPPED_TROOM",
	"TX_FORWARD_ENQUEUE_FAIL",
	"RX_FORWARD_ENQUEUE_FAIL",
	"RX_INVALID_VERSION",
	"RX_INVALID_EPOCH",
	"RX_MALFORMED",
	"RX_CIPHER_FAIL",
	"RX_AUTH_FAIL",
	"RX_CAPWAP_CLASSIFY_FAIL",
	"RX_SINGLE_REC_DGRAM",
	"RX_MULTI_REC_DGRAM",
	"RX_REPLAY_FAIL",
	"RX_REPLAY_DUPLICATE",
	"RX_REPLAY_OUT_OF_WINDOW",
	"OUTFLOW_QUEUE_FULL",
	"DECAP_QUEUE_FULL",
	"PBUF_ALLOC_FAIL",
	"PBUF_COPY_FAIL",
	"EPOCH",
	"TX_SEQ_HIGH",
	"TX_SEQ_LOW",
};

/*
 * nss_stats_str_gre_tunnel_session_stats
 *	GRE Tunnel statistics strings for nss session stats
 */
static int8_t *nss_stats_str_gre_tunnel_session_debug_stats[NSS_STATS_GRE_TUNNEL_SESSION_MAX] = {
	"RX_PKTS",
	"TX_PKTS",
	"RX_DROPPED",
	"RX_MALFORMED",
	"RX_INVALID_PROT",
	"DECAP_QUEUE_FULL",
	"RX_SINGLE_REC_DGRAM",
	"RX_INVALID_REC_DGRAM",
	"BUFFER_ALLOC_FAIL",
	"BUFFER_COPY_FAIL",
	"OUTFLOW_QUEUE_FULL",
	"TX_DROPPED_HROOM",
	"RX_CBUFFER_ALLOC_FAIL",
	"RX_CENQUEUE_FAIL",
	"RX_DECRYPT_DONE",
	"RX_FORWARD_ENQUEUE_FAIL",
	"TX_CBUFFER_ALLOC_FAIL",
	"TX_CENQUEUE_FAIL",
	"TX_DROPPED_TROOM",
	"TX_FORWARD_ENQUEUE_FAIL",
	"TX_CIPHER_DONE",
	"CRYPTO_NOSUPP",
	"RX_DROPPED_MH_VERSION",
};

/*
 * nss_stats_str_l2tpv2_session_stats
 *	l2tpv2 statistics strings for nss session stats
 */
static int8_t *nss_stats_str_l2tpv2_session_debug_stats[NSS_STATS_L2TPV2_SESSION_MAX] = {
	"RX_PPP_LCP_PKTS",
	"RX_EXP_PKTS",
	"ENCAP_PBUF_ALLOC_FAIL",
	"DECAP_PBUF_ALLOC_FAIL"
};

/*
 * nss_stats_str_map_t_instance_stats
 *	map_t statistics strings for nss session stats
 */
static int8_t *nss_stats_str_map_t_instance_debug_stats[NSS_STATS_MAP_T_MAX] = {
	"MAP_T_V4_TO_V6_PBUF_EXCEPTION_PKTS",
	"MAP_T_V4_TO_V6_PBUF_NO_MATCHING_RULE",
	"MAP_T_V4_TO_V6_PBUF_NOT_TCP_OR_UDP",
	"MAP_T_V4_TO_V6_RULE_ERR_LOCAL_PSID",
	"MAP_T_V4_TO_V6_RULE_ERR_LOCAL_IPV6",
	"MAP_T_V4_TO_V6_RULE_ERR_REMOTE_PSID",
	"MAP_T_V4_TO_V6_RULE_ERR_REMOTE_EA_BITS",
	"MAP_T_V4_TO_V6_RULE_ERR_REMOTE_IPV6",
	"MAP_T_V6_TO_V4_PBUF_EXCEPTION_PKTS",
	"MAP_T_V6_TO_V4_PBUF_NO_MATCHING_RULE",
	"MAP_T_V6_TO_V4_PBUF_NOT_TCP_OR_UDP",
	"MAP_T_V6_TO_V4_RULE_ERR_LOCAL_IPV4",
	"MAP_T_V6_TO_V4_RULE_ERR_REMOTE_IPV4"
};

 /*
 * nss_stats_str_gre_base_stats
 *	GRE debug statistics strings for base types
 */
static int8_t *nss_stats_str_gre_base_debug_stats[NSS_STATS_GRE_BASE_DEBUG_MAX] = {
	"GRE_BASE_RX_PACKETS",
	"GRE_BASE_RX_DROPPED",
	"GRE_BASE_EXP_ETH_HDR_MISSING",
	"GRE_BASE_EXP_ETH_TYPE_NON_IP",
	"GRE_BASE_EXP_IP_UNKNOWN_PROTOCOL",
	"GRE_BASE_EXP_IP_HEADER_INCOMPLETE",
	"GRE_BASE_EXP_IP_BAD_TOTAL_LENGTH",
	"GRE_BASE_EXP_IP_BAD_CHECKSUM",
	"GRE_BASE_EXP_IP_DATAGRAM_INCOMPLETE",
	"GRE_BASE_EXP_IP_FRAGMENT",
	"GRE_BASE_EXP_IP_OPTIONS_INCOMPLETE",
	"GRE_BASE_EXP_IP_WITH_OPTIONS",
	"GRE_BASE_EXP_IPV6_UNKNOWN_PROTOCOL",
	"GRE_BASE_EXP_IPV6_HEADER_INCOMPLETE",
	"GRE_BASE_EXP_GRE_UNKNOWN_SESSION",
	"GRE_BASE_EXP_GRE_NODE_INACTIVE",
};

/*
 * nss_stats_str_gre_session_stats
 *	GRE debug statistics strings for sessions
 */
static int8_t *nss_stats_str_gre_session_debug_stats[NSS_STATS_GRE_SESSION_DEBUG_MAX] = {
	"GRE_SESSION_PBUF_ALLOC_FAIL",
	"GRE_SESSION_DECAP_FORWARD_ENQUEUE_FAIL",
	"GRE_SESSION_ENCAP_FORWARD_ENQUEUE_FAIL",
	"GRE_SESSION_DECAP_TX_FORWARDED",
	"GRE_SESSION_ENCAP_RX_RECEIVED",
	"GRE_SESSION_ENCAP_RX_DROPPED",
	"GRE_SESSION_ENCAP_RX_LINEAR_FAIL",
	"GRE_SESSION_EXP_RX_KEY_ERROR",
	"GRE_SESSION_EXP_RX_SEQ_ERROR",
	"GRE_SESSION_EXP_RX_CS_ERROR",
	"GRE_SESSION_EXP_RX_FLAG_MISMATCH",
	"GRE_SESSION_EXP_RX_MALFORMED",
	"GRE_SESSION_EXP_RX_INVALID_PROTOCOL",
	"GRE_SESSION_EXP_RX_NO_HEADROOM",
};

/*
 * nss_stats_str_ppe_conn
 *	PPE statistics strings for nss flow stats
 */
static int8_t *nss_stats_str_ppe_conn[NSS_STATS_PPE_CONN_MAX] = {
	"v4 routed flows",
	"v4 bridge flows",
	"v4 conn create req",
	"v4 conn create fail",
	"v4 conn destroy req",
	"v4 conn destroy fail",
	"v4 conn MC create req",
	"v4 conn MC create fail",
	"v4 conn MC update req",
	"v4 conn MC update fail",
	"v4 conn MC delete req",
	"v4 conn MC delete fail",

	"v6 routed flows",
	"v6 bridge flows",
	"v6 conn create req",
	"v6 conn create fail",
	"v6 conn destroy req",
	"v6 conn destroy fail",
	"v6 conn MC create req",
	"v6 conn MC create fail",
	"v6 conn MC update req",
	"v6 conn MC update fail",
	"v6 conn MC delete req",
	"v6 conn MC delete fail",

	"conn fail - vp full",
	"conn fail - nexthop full",
	"conn fail - flow full",
	"conn fail - host full",
	"conn fail - pub-ip full",
	"conn fail - port not setup",
	"conn fail - rw fifo full",
	"conn fail - flow cmd failure",
	"conn fail - unknown proto",
	"conn fail - ppe not responding",
	"conn fail - CE opaque invalid",
	"conn fail - fqg full"
};

/*
 * nss_stats_str_ppe_l3
 *	PPE statistics strings for nss debug stats
 */
static int8_t *nss_stats_str_ppe_l3[NSS_STATS_PPE_L3_MAX] = {
	"PPE L3 dbg reg 0",
	"PPE L3 dbg reg 1",
	"PPE L3 dbg reg 2",
	"PPE L3 dbg reg 3",
	"PPE L3 dbg reg 4",
	"PPE L3 dbg reg port",
};

/*
 * nss_stats_str_ppe_code
 *	PPE statistics strings for nss debug stats
 */
static int8_t *nss_stats_str_ppe_code[NSS_STATS_PPE_CODE_MAX] = {
	"PPE CPU_CODE",
	"PPE DROP_CODE",
};

/*
 * nss_stats_str_ppe_dc
 *	PPE statistics strings for drop code
 */
static int8_t *nss_stats_str_ppe_dc[NSS_STATS_PPE_DROP_CODE_MAX] = {
	"PPE_DROP_CODE_NONE",
	"PPE_DROP_CODE_EXP_UNKNOWN_L2_PORT",
	"PPE_DROP_CODE_EXP_PPPOE_WRONG_VER_TYPE",
	"PPE_DROP_CODE_EXP_PPPOE_WRONG_CODE",
	"PPE_DROP_CODE_EXP_PPPOE_UNSUPPORTED_PPP_PROT",
	"PPE_DROP_CODE_EXP_IPV4_WRONG_VER",
	"PPE_DROP_CODE_EXP_IPV4_SMALL_IHL",
	"PPE_DROP_CODE_EXP_IPV4_WITH_OPTION",
	"PPE_DROP_CODE_EXP_IPV4_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV4_BAD_TOTAL_LEN",
	"PPE_DROP_CODE_EXP_IPV4_DATA_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV4_FRAG",
	"PPE_DROP_CODE_EXP_IPV4_PING_OF_DEATH",
	"PPE_DROP_CODE_EXP_IPV4_SNALL_TTL",
	"PPE_DROP_CODE_EXP_IPV4_UNK_IP_PROT",
	"PPE_DROP_CODE_EXP_IPV4_CHECKSUM_ERR",
	"PPE_DROP_CODE_EXP_IPV4_INV_SIP",
	"PPE_DROP_CODE_EXP_IPV4_INV_DIP",
	"PPE_DROP_CODE_EXP_IPV4_LAND_ATTACK",
	"PPE_DROP_CODE_EXP_IPV4_AH_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV4_AH_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_IPV4_ESP_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_WRONG_VER",
	"PPE_DROP_CODE_EXP_IPV6_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_BAD_PAYLOAD_LEN",
	"PPE_DROP_CODE_EXP_IPV6_DATA_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_WITH_EXT_HDR",
	"PPE_DROP_CODE_EXP_IPV6_SMALL_HOP_LIMIT",
	"PPE_DROP_CODE_EXP_IPV6_INV_SIP",
	"PPE_DROP_CODE_EXP_IPV6_INV_DIP",
	"PPE_DROP_CODE_EXP_IPV6_LAND_ATTACK",
	"PPE_DROP_CODE_EXP_IPV6_FRAG",
	"PPE_DROP_CODE_EXP_IPV6_PING_OF_DEATH",
	"PPE_DROP_CODE_EXP_IPV6_WITH_MORE_EXT_HDR",
	"PPE_DROP_CODE_EXP_IPV6_UNK_LAST_NEXT_HDR",
	"PPE_DROP_CODE_EXP_IPV6_MOBILITY_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_MOBILITY_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_IPV6_AH_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_AH_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_IPV6_ESP_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_ESP_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_IPV6_OTHER_EXT_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_IPV6_OTHER_EXT_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_TCP_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_TCP_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_TCP_SMAE_SP_DP",
	"PPE_DROP_CODE_EXP_TCP_SMALL_DATA_OFFSET",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_0",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_1",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_2",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_3",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_4",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_5",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_6",
	"PPE_DROP_CODE_EXP_TCP_FLAGS_7",
	"PPE_DROP_CODE_EXP_TCP_CHECKSUM_ERR",
	"PPE_DROP_CODE_EXP_UDP_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_UDP_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_UDP_SMAE_SP_DP",
	"PPE_DROP_CODE_EXP_UDP_BAD_LEN",
	"PPE_DROP_CODE_EXP_UDP_DATA_INCOMPLETE",
	"PPE_DROP_CODE_EXP_UDP_CHECKSUM_ERR",
	"PPE_DROP_CODE_EXP_UDP_LITE_HDR_INCOMPLETE",
	"PPE_DROP_CODE_EXP_UDP_LITE_HDR_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_UDP_LITE_SMAE_SP_DP",
	"PPE_DROP_CODE_EXP_UDP_LITE_CSM_COV_1_TO_7",
	"PPE_DROP_CODE_EXP_UDP_LITE_CSM_COV_TOO_LONG",
	"PPE_DROP_CODE_EXP_UDP_LITE_CSM_COV_CROSS_BORDER",
	"PPE_DROP_CODE_EXP_UDP_LITE_CHECKSUM_ERR",
	"PPE_DROP_CODE_L3_MC_BRIDGE_ACTION",
	"PPE_DROP_CODE_L3_NO_ROUTE_PREHEAD_NAT_ACTION",
	"PPE_DROP_CODE_L3_NO_ROUTE_PREHEAD_NAT_ERROR",
	"PPE_DROP_CODE_L3_ROUTE_ACTION",
	"PPE_DROP_CODE_L3_NO_ROUTE_ACTION",
	"PPE_DROP_CODE_L3_NO_ROUTE_NH_INVALID_ACTION",
	"PPE_DROP_CODE_L3_NO_ROUTE_PREHEAD_ACTION",
	"PPE_DROP_CODE_L3_BRIDGE_ACTION",
	"PPE_DROP_CODE_L3_FLOW_ACTION",
	"PPE_DROP_CODE_L3_FLOW_MISS_ACTION",
	"PPE_DROP_CODE_L2_EXP_MRU_FAIL",
	"PPE_DROP_CODE_L2_EXP_MTU_FAIL",
	"PPE_DROP_CODE_L3_EXP_IP_PREFIX_BC",
	"PPE_DROP_CODE_L3_EXP_MTU_FAIL",
	"PPE_DROP_CODE_L3_EXP_MRU_FAIL",
	"PPE_DROP_CODE_L3_EXP_ICMP_RDT",
	"PPE_DROP_CODE_FAKE_MAC_HEADER_ERR",
	"PPE_DROP_CODE_L3_EXP_IP_RT_TTL_ZERO",
	"PPE_DROP_CODE_L3_FLOW_SERVICE_CODE_LOOP",
	"PPE_DROP_CODE_L3_FLOW_DE_ACCELEARTE",
	"PPE_DROP_CODE_L3_EXP_FLOW_SRC_IF_CHK_FAIL",
	"PPE_DROP_CODE_L3_FLOW_SYNC_TOGGLE_MISMATCH",
	"PPE_DROP_CODE_L3_EXP_MTU_DF_FAIL",
	"PPE_DROP_CODE_L3_EXP_PPPOE_MULTICAST",
	"PPE_DROP_CODE_IPV4_SG_UNKNOWN",
	"PPE_DROP_CODE_IPV6_SG_UNKNOWN",
	"PPE_DROP_CODE_ARP_SG_UNKNOWN",
	"PPE_DROP_CODE_ND_SG_UNKNOWN",
	"PPE_DROP_CODE_IPV4_SG_VIO",
	"PPE_DROP_CODE_IPV6_SG_VIO",
	"PPE_DROP_CODE_ARP_SG_VIO",
	"PPE_DROP_CODE_ND_SG_VIO",
	"PPE_DROP_CODE_L2_NEW_MAC_ADDRESS",
	"PPE_DROP_CODE_L2_HASH_COLLISION",
	"PPE_DROP_CODE_L2_STATION_MOVE",
	"PPE_DROP_CODE_L2_LEARN_LIMIT",
	"PPE_DROP_CODE_L2_SA_LOOKUP_ACTION",
	"PPE_DROP_CODE_L2_DA_LOOKUP_ACTION",
	"PPE_DROP_CODE_APP_CTRL_ACTION",
	"PPE_DROP_CODE_IN_VLAN_FILTER_ACTION",
	"PPE_DROP_CODE_IN_VLAN_XLT_MISS",
	"PPE_DROP_CODE_EG_VLAN_FILTER_DROP",
	"PPE_DROP_CODE_ACL_PRE_ACTION",
	"PPE_DROP_CODE_ACL_POST_ACTION",
	"PPE_DROP_CODE_MC_BC_SA",
	"PPE_DROP_CODE_NO_DESTINATION",
	"PPE_DROP_CODE_STG_IN_FILTER",
	"PPE_DROP_CODE_STG_EG_FILTER",
	"PPE_DROP_CODE_SOURCE_FILTER_FAIL",
	"PPE_DROP_CODE_TRUNK_SEL_FAIL",
	"PPE_DROP_CODE_TX_EN_FAIL",
	"PPE_DROP_CODE_VLAN_TAG_FMT",
	"PPE_DROP_CODE_CRC_ERR",
	"PPE_DROP_CODE_PAUSE_FRAME",
	"PPE_DROP_CODE_PROMISC",
	"PPE_DROP_CODE_ISOLATION",
	"PPE_DROP_CODE_MGMT_APP",
	"PPE_DROP_CODE_FAKE_L2_PROT_ERR",
	"PPE_DROP_CODE_POLICER",
};

/*
 * nss_stats_str_ppe_cc
 *	PPE statistics strings for cpu code
 */
static int8_t *nss_stats_str_ppe_cc[NSS_STATS_PPE_CPU_CODE_MAX] = {
	"PPE_CPU_CODE_FORWARDING",
	"PPE_CPU_CODE_EXP_UNKNOWN_L2_PROT",
	"PPE_CPU_CODE_EXP_PPPOE_WRONG_VER_TYPE",
	"PPE_CPU_CODE_EXP_WRONG_CODE",
	"PPE_CPU_CODE_EXP_PPPOE_UNSUPPORTED_PPP_PROT",
	"PPE_CPU_CODE_EXP_WRONG_VER",
	"PPE_CPU_CODE_EXP_SMALL_IHL",
	"PPE_CPU_CODE_EXP_WITH_OPTION",
	"PPE_CPU_CODE_EXP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV4_BAD_TOTAL_LEN",
	"PPE_CPU_CODE_EXP_DATA_INCOMPLETE",
	"PPE_CPU_CODE_IPV4_FRAG",
	"PPE_CPU_CODE_EXP_IPV4_PING_OF_DEATH",
	"PPE_CPU_CODE_EXP_SNALL_TTL",
	"PPE_CPU_CODE_EXP_IPV4_UNK_IP_PROT",
	"PPE_CPU_CODE_EXP_CHECKSUM_ERR",
	"PPE_CPU_CODE_EXP_INV_SIP",
	"PPE_CPU_CODE_EXP_INV_DIP",
	"PPE_CPU_CODE_EXP_LAND_ATTACK",
	"PPE_CPU_CODE_EXP_IPV4_AH_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV4_AH_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_IPV4_ESP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_WRONG_VER",
	"PPE_CPU_CODE_EXP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_BAD_PAYLOAD_LEN",
	"PPE_CPU_CODE_EXP_DATA_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_WITH_EXT_HDR",
	"PPE_CPU_CODE_EXP_IPV6_SMALL_HOP_LIMIT",
	"PPE_CPU_CODE_EXP_INV_SIP",
	"PPE_CPU_CODE_EXP_INV_DIP",
	"PPE_CPU_CODE_EXP_LAND_ATTACK",
	"PPE_CPU_CODE_IPV6_FRAG",
	"PPE_CPU_CODE_EXP_IPV6_PING_OF_DEATH",
	"PPE_CPU_CODE_EXP_IPV6_WITH_EXT_HDR",
	"PPE_CPU_CODE_EXP_IPV6_UNK_NEXT_HDR",
	"PPE_CPU_CODE_EXP_IPV6_MOBILITY_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_MOBILITY_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_IPV6_AH_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_AH_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_IPV6_ESP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_ESP_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_IPV6_OTHER_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_IPV6_OTHER_EXT_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_TCP_HDR_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_TCP_SMAE_SP_DP",
	"PPE_CPU_CODE_EXP_TCP_SMALL_DATA_OFFSET",
	"PPE_CPU_CODE_EXP_FLAGS_0",
	"PPE_CPU_CODE_EXP_FLAGS_1",
	"PPE_CPU_CODE_EXP_FLAGS_2",
	"PPE_CPU_CODE_EXP_FLAGS_3",
	"PPE_CPU_CODE_EXP_FLAGS_4",
	"PPE_CPU_CODE_EXP_FLAGS_5",
	"PPE_CPU_CODE_EXP_FLAGS_6",
	"PPE_CPU_CODE_EXP_FLAGS_7",
	"PPE_CPU_CODE_EXP_CHECKSUM_ERR",
	"PPE_CPU_CODE_EXP_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_UDP_HDR_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_UDP_SMAE_SP_DP",
	"PPE_CPU_CODE_EXP_BAD_LEN",
	"PPE_CPU_CODE_EXP_DATA_INCOMPLETE",
	"PPE_CPU_CODE_EXP_CHECKSUM_ERR",
	"PPE_CPU_CODE_EXP_UDP_LITE_HDR_INCOMPLETE",
	"PPE_CPU_CODE_EXP_UDP_LITE_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_UDP_LITE_SP_DP",
	"PPE_CPU_CODE_EXP_UDP_LITE_CSM_COV_TO_7",
	"PPE_CPU_CODE_EXP_UDP_LITE_CSM_TOO_LONG",
	"PPE_CPU_CODE_EXP_UDP_LITE_CSM_CROSS_BORDER",
	"PPE_CPU_CODE_EXP_UDP_LITE_CHECKSUM_ERR",
	"PPE_CPU_CODE_EXP_FAKE_L2_PROT_ERR",
	"PPE_CPU_CODE_EXP_FAKE_MAC_HEADER_ERR",
	"PPE_CPU_CODE_BITMAP_MAX",
	"PPE_CPU_CODE_L2_MRU_FAIL",
	"PPE_CPU_CODE_L2_MTU_FAIL",
	"PPE_CPU_CODE_L3_EXP_IP_PREFIX_BC",
	"PPE_CPU_CODE_L3_MTU_FAIL",
	"PPE_CPU_CODE_L3_MRU_FAIL",
	"PPE_CPU_CODE_L3_ICMP_RDT",
	"PPE_CPU_CODE_L3_EXP_IP_RT_TO_ME",
	"PPE_CPU_CODE_L3_EXP_IP_TTL_ZERO",
	"PPE_CPU_CODE_L3_FLOW_SERVICE_CODE_LOOP",
	"PPE_CPU_CODE_L3_DE_ACCELERATE",
	"PPE_CPU_CODE_L3_EXP_FLOW_SRC_CHK_FAIL",
	"PPE_CPU_CODE_L3_FLOW_SYNC_TOGGLE_MISMATCH",
	"PPE_CPU_CODE_L3_EXP_MTU_DF_FAIL",
	"PPE_CPU_CODE_L3_PPPOE_MULTICAST",
	"PPE_CPU_CODE_MGMT_OFFSET",
	"PPE_CPU_CODE_MGMT_EAPOL",
	"PPE_CPU_CODE_PPPOE_DIS",
	"PPE_CPU_CODE_MGMT_IGMP",
	"PPE_CPU_CODE_ARP_REQ",
	"PPE_CPU_CODE_ARP_REP",
	"PPE_CPU_CODE_MGMT_DHCPv4",
	"PPE_CPU_CODE_MGMT_MLD",
	"PPE_CPU_CODE_MGMT_NS",
	"PPE_CPU_CODE_MGMT_NA",
	"PPE_CPU_CODE_MGMT_DHCPv6",
	"PPE_CPU_CODE_PTP_OFFSET",
	"PPE_CPU_CODE_PTP_SYNC",
	"PPE_CPU_CODE_FOLLOW_UP",
	"PPE_CPU_CODE_DELAY_REQ",
	"PPE_CPU_CODE_DELAY_RESP",
	"PPE_CPU_CODE_PDELAY_REQ",
	"PPE_CPU_CODE_PDELAY_RESP",
	"PPE_CPU_CODE_PTP_PDELAY_RESP_FOLLOW_UP",
	"PPE_CPU_CODE_PTP_ANNOUNCE",
	"PPE_CPU_CODE_PTP_MANAGEMENT",
	"PPE_CPU_CODE_PTP_SIGNALING",
	"PPE_CPU_CODE_PTP_RSV_MSG",
	"PPE_CPU_CODE_SG_UNKNOWN",
	"PPE_CPU_CODE_SG_UNKNOWN",
	"PPE_CPU_CODE_SG_UNKNOWN",
	"PPE_CPU_CODE_SG_UNKNOWN",
	"PPE_CPU_CODE_SG_VIO",
	"PPE_CPU_CODE_SG_VIO",
	"PPE_CPU_CODE_SG_VIO",
	"PPE_CPU_CODE_SG_VIO",
	"PPE_CPU_CODE_L3_ROUTING_IP_TO_ME",
	"PPE_CPU_CODE_L3_SNAT_ACTION",
	"PPE_CPU_CODE_L3_DNAT_ACTION",
	"PPE_CPU_CODE_L3_RT_ACTION",
	"PPE_CPU_CODE_L3_BR_ACTION",
	"PPE_CPU_CODE_L3_BRIDGE_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_PREHEAD_RT_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_PREHEAD_SNAPT_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_PREHEAD_DNAPT_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_PREHEAD_SNAT_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_PREHEAD_DNAT_ACTION",
	"PPE_CPU_CODE_L3_NO_ROUTE_NAT_ACTION",
	"PPE_CPU_CODE_L3_NO_ROUTE_NAT_ERROR",
	"PPE_CPU_CODE_ROUTE_ACTION",
	"PPE_CPU_CODE_L3_ROUTE_ACTION",
	"PPE_CPU_CODE_L3_NO_ROUTE_INVALID_ACTION",
	"PPE_CPU_CODE_L3_NO_ROUTE_PREHEAD_ACTION",
	"PPE_CPU_CODE_BRIDGE_ACTION",
	"PPE_CPU_CODE_FLOW_ACTION",
	"PPE_CPU_CODE_L3_MISS_ACTION",
	"PPE_CPU_CODE_L2_MAC_ADDRESS",
	"PPE_CPU_CODE_HASH_COLLISION",
	"PPE_CPU_CODE_STATION_MOVE",
	"PPE_CPU_CODE_LEARN_LIMIT",
	"PPE_CPU_CODE_L2_LOOKUP_ACTION",
	"PPE_CPU_CODE_L2_LOOKUP_ACTION",
	"PPE_CPU_CODE_CTRL_ACTION",
	"PPE_CPU_CODE_IN_FILTER_ACTION",
	"PPE_CPU_CODE_IN_XLT_MISS",
	"PPE_CPU_CODE_EG_FILTER_DROP",
	"PPE_CPU_CODE_PRE_ACTION",
	"PPE_CPU_CODE_POST_ACTION",
	"PPE_CPU_CODE_CODE_ACTION",
};

/*
 * nss_stats_str_ppt_session_stats
 *	PPTP statistics strings for nss session stats
 */
static int8_t *nss_stats_str_pptp_session_debug_stats[NSS_STATS_PPTP_SESSION_MAX] = {
	"ENCAP_RX_PACKETS",
	"ENCAP_RX_BYTES",
	"ENCAP_TX_PACKETS",
	"ENCAP_TX_BYTES",
	"ENCAP_RX_DROP",
	"DECAP_RX_PACKETS",
	"DECAP_RX_BYTES",
	"DECAP_TX_PACKETS",
	"DECAP_TX_BYTES",
	"DECAP_RX_DROP",
	"ENCAP_HEADROOM_ERR",
	"ENCAP_SMALL_SIZE",
	"ENCAP_PNODE_ENQUEUE_FAIL",
	"DECAP_NO_SEQ_NOR_ACK",
	"DECAP_INVAL_GRE_FLAGS",
	"DECAP_INVAL_GRE_PROTO",
	"DECAP_WRONG_SEQ",
	"DECAP_INVAL_PPP_HDR",
	"DECAP_PPP_LCP",
	"DECAP_UNSUPPORTED_PPP_PROTO",
	"DECAP_PNODE_ENQUEUE_FAIL",
};

/*
 * nss_stats_str_trustsec_tx
 *	Trustsec TX stats strings
 */
static int8_t *nss_stats_str_trustsec_tx[NSS_STATS_TRUSTSEC_TX_MAX] = {
	"INVALID_SRC",
	"UNCONFIGURED_SRC",
	"HEADROOM_NOT_ENOUGH",
};

/*
 * nss_stats_ipv4_read()
 *	Read IPV4 stats
 */
static ssize_t nss_stats_ipv4_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_IPV4_MAX + 3) + (NSS_EXCEPTION_EVENT_IPV4_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that exception event count is larger than other statistics count for IPv4
	 */
	stats_shadow = kzalloc(NSS_EXCEPTION_EVENT_IPV4_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "ipv4 stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_IPV4_RX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * IPv4 node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv4 node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV4_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv4[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV4_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv4[i], stats_shadow[i]);
	}

	/*
	 * Exception stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv4 exception stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV4_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_if_exception_ipv4[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV4_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_exception_ipv4[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv4 stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_ipv4_reasm_read()
 *	Read IPV4 reassembly stats
 */
static ssize_t nss_stats_ipv4_reasm_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_IPV4_REASM_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_IPV4_REASM_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "ipv4 reasm stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_IPV4_REASM_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * IPv4 reasm node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv4 reasm node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV4_REASM_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv4_reasm[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV4_REASM_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv4_reasm[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv4 reasm stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_ipv6_read()
 *	Read IPV6 stats
 */
static ssize_t nss_stats_ipv6_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_IPV6_MAX + 3) + (NSS_EXCEPTION_EVENT_IPV6_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that exception event count is larger than other statistics count for IPv4
	 */
	stats_shadow = kzalloc(NSS_EXCEPTION_EVENT_IPV6_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "ipv6 stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_IPV6_RX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * IPv6 node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV6_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv6[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV6_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv6[i], stats_shadow[i]);
	}

	/*
	 * Exception stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 exception stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV6_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_if_exception_ipv6[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV6_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_exception_ipv6[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_ipv6_reasm_read()
 *	Read IPV6 reassembly stats
 */
static ssize_t nss_stats_ipv6_reasm_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_IPV6_REASM_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_IPV6_REASM_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "ipv6 reasm stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_IPV6_REASM_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * Ipv6 reasm node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 reasm node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV6_REASM_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv6_reasm[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV6_REASM_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv6_reasm[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 reasm stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_port_stats_read()
 *	Read EDMA port stats
 */
static ssize_t nss_stats_edma_port_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_edma.port[data->edma_id].port_stats[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_err_stats_read()
 *	Read EDMA err stats
 */
static ssize_t nss_stats_edma_err_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_ERR_STATS_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma error stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma error stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EDMA_ERR_STATS_MAX); i++)
		stats_shadow[i] = nss_top_main.stats_edma.misc_err[i];

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EDMA_ERR_STATS_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_err_map[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma error stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_port_type_read()
 *	Read EDMA port type
 */
static ssize_t nss_stats_edma_port_type_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (1 + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t port_type;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma port type start:\n\n");
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d type:\n\n", data->edma_id);

	/*
	 * Port type
	 */
	spin_lock_bh(&nss_top_main.stats_lock);
	port_type = nss_top_main.stats_edma.port[data->edma_id].port_type;
	spin_unlock_bh(&nss_top_main.stats_lock);

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"port_type = %s\n", nss_stats_str_edma_port_type[port_type]);

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);

	return bytes_read;
}

/*
 * nss_stats_edma_port_ring_map_read()
 *	Read EDMA port ring map
 */
static ssize_t nss_stats_edma_port_ring_map_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (4 + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma port ring map start:\n\n");

	/*
	 * Port ring map
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d ring map:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_PORT_RING_MAP_MAX; i++) {
		stats_shadow[i] = nss_top_main.stats_edma.port[data->edma_id].port_ring_map[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_PORT_RING_MAP_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_port_ring_map[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_txring_read()
 *	Read EDMA Tx ring stats
 */
static ssize_t nss_stats_edma_txring_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_EDMA_TX_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Tx ring stats start:\n\n");

	/*
	 * Tx ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Tx ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_STATS_EDMA_TX_MAX; i++) {
		stats_shadow[i] = nss_top_main.stats_edma.tx_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_STATS_EDMA_TX_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_tx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Tx ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_rxring_read()
 *	Read EDMA rxring stats
 */
static ssize_t nss_stats_edma_rxring_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_EDMA_RX_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Rx ring stats start:\n\n");

	/*
	 * RX ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Rx ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_STATS_EDMA_RX_MAX; i++) {
		stats_shadow[i] = nss_top_main.stats_edma.rx_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_STATS_EDMA_RX_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_rx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Rx ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_txcmplring_read()
 *	Read EDMA txcmplring stats
 */
static ssize_t nss_stats_edma_txcmplring_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_EDMA_TXCMPL_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Tx cmpl ring stats start:\n\n");

	/*
	 * Tx cmpl ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Tx cmpl ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_STATS_EDMA_TXCMPL_MAX; i++) {
		stats_shadow[i] = nss_top_main.stats_edma.txcmpl_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_STATS_EDMA_TXCMPL_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_txcmpl[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Tx cmpl ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_edma_rxfillring_read()
 *	Read EDMA rxfillring stats
 */
static ssize_t nss_stats_edma_rxfillring_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_EDMA_RXFILL_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Rx fill ring stats start:\n\n");

	/*
	 * Rx fill ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Rx fill ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_STATS_EDMA_RXFILL_MAX; i++) {
		stats_shadow[i] = nss_top_main.stats_edma.rxfill_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_STATS_EDMA_RXFILL_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_edma_rxfill[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Rx fill ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_eth_rx_read()
 *	Read ETH_RX stats
 */
static ssize_t nss_stats_eth_rx_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_ETH_RX_MAX + 3) + (NSS_EXCEPTION_EVENT_ETH_RX_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "eth_rx stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_ETH_RX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * eth_rx node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\neth_rx node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_ETH_RX_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_eth_rx[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_ETH_RX_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_eth_rx[i], stats_shadow[i]);
	}

	/*
	 * Exception stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\neth_rx exception stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_EXCEPTION_EVENT_ETH_RX_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_if_exception_eth_rx[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EXCEPTION_EVENT_ETH_RX_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_exception_eth_rx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\neth_rx stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_n2h_read()
 *	Read N2H stats
 */
static ssize_t nss_stats_n2h_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_N2H_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	int max = NSS_STATS_N2H_MAX - NSS_STATS_NODE_MAX;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_N2H_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "n2h stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.nss[0].stats_n2h[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * N2H node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nn2h node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = NSS_STATS_NODE_MAX; (i < NSS_STATS_N2H_MAX); i++) {
		stats_shadow[i] = nss_top_main.nss[0].stats_n2h[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < max; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_n2h[i], stats_shadow[i + NSS_STATS_NODE_MAX]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nn2h stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_lso_rx_read()
 *	Read LSO_RX stats
 */
static ssize_t nss_stats_lso_rx_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_LSO_RX_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_LSO_RX_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "lso_rx stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_LSO_RX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * lso_rx node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nlso_rx node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_LSO_RX_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_lso_rx[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_STATS_LSO_RX_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_lso_rx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nlso_rx stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_drv_read()
 *	Read HLOS driver stats
 */
static ssize_t nss_stats_drv_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_DRV_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_DRV_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "drv stats start:\n\n");
	for (i = 0; (i < NSS_STATS_DRV_MAX); i++) {
		stats_shadow[i] = NSS_PKT_STATS_READ(&nss_top_main.stats_drv[i]);
	}

	for (i = 0; (i < NSS_STATS_DRV_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_drv[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ndrv stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_pppoe_read()
 *	Read PPPoE stats
 */
static ssize_t nss_stats_pppoe_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i, j, k;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_PPPOE_MAX + 3) +
					((NSS_MAX_PHYSICAL_INTERFACES * NSS_PPPOE_NUM_SESSION_PER_INTERFACE * (NSS_PPPOE_EXCEPTION_EVENT_MAX + 5)) + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "pppoe stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_PPPOE_RX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				 "%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * PPPoE node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npppoe node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_PPPOE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_pppoe[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_PPPOE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_pppoe[i], stats_shadow[i]);
	}

	/*
	 * Exception stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nException PPPoE:\n\n");

	for (j = 1; j <= NSS_MAX_PHYSICAL_INTERFACES; j++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nInterface %d:\n\n", j);

		spin_lock_bh(&nss_top_main.stats_lock);
		for (k = 1; k <= NSS_PPPOE_NUM_SESSION_PER_INTERFACE; k++) {
			for (i = 0; (i < NSS_PPPOE_EXCEPTION_EVENT_MAX); i++) {
				stats_shadow_pppoe_except[k - 1][i] = nss_top_main.stats_if_exception_pppoe[j][k][i];
			}
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		for (k = 1; k <= NSS_PPPOE_NUM_SESSION_PER_INTERFACE; k++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. Session\n", k);
			for (i = 0; (i < NSS_PPPOE_EXCEPTION_EVENT_MAX); i++) {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
						"%s = %llu\n",
						nss_stats_str_if_exception_pppoe[i],
						stats_shadow_pppoe_except[k - 1][i]);
			}
		}

	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npppoe stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_gmac_read()
 *	Read GMAC stats
 */
static ssize_t nss_stats_gmac_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, id;

	/*
	 * max output lines = ((#stats + start tag + one blank) * #GMACs) + start/end tag + 3 blank
	 */
	uint32_t max_output_lines = ((NSS_STATS_GMAC_MAX + 2) * NSS_MAX_PHYSICAL_INTERFACES) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_GMAC_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "gmac stats start:\n\n");

	for (id = 0; id < NSS_MAX_PHYSICAL_INTERFACES; id++) {
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_GMAC_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_gmac[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "GMAC ID: %d\n", id);
		for (i = 0; (i < NSS_STATS_GMAC_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_gmac[i], stats_shadow[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngmac stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_wifi_read()
 * 	Read wifi statistics
 */
static ssize_t nss_stats_wifi_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, id;

	/*
	 * max output lines = ((#stats + start tag + one blank) * #WIFI RADIOs) + start/end tag + 3 blank
	 */
	uint32_t max_output_lines = ((NSS_STATS_WIFI_MAX + 2) * NSS_MAX_WIFI_RADIO_INTERFACES) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_WIFI_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "wifi stats start:\n\n");

	for (id = 0; id < NSS_MAX_WIFI_RADIO_INTERFACES; id++) {
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_WIFI_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_wifi[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "WIFI ID: %d\n", id);
		for (i = 0; (i < NSS_STATS_WIFI_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifi[i], stats_shadow[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,"\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nwifi stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_wifili_read()
 * 	Read wifili statistics
 */
static ssize_t nss_stats_wifili_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, j;

	/*
	 * max output lines = ((#stats + eight blank lines) * #WIFILI #STATS) + start/end tag + 3 blank
	 */
	uint32_t max_output_lines = (((NSS_STATS_WIFILI_MAX + 9) * NSS_WIFILI_MAX_PDEV_NUM_MSG)+
									NSS_STATS_WIFILI_WBM_MAX + 5);
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Take max of all wifili stats
	 *
	 * NOTE: txrx stats is bigger of all stats
	 */
	stats_shadow = kzalloc(NSS_STATS_WIFILI_TXRX_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "wifili stats start:\n\n");

	for (i = 0; i < NSS_WIFILI_MAX_PDEV_NUM_MSG; i++) {

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "WIFILI ID: %d\n", i);

		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_TXRX_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_txrx[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_txrx[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TCL ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_TCL_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_tcl_ring[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_tcl[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TCL comp stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_TX_DESC_FREE_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_tx_comp[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_tx_comp[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng reo ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_REO_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_reo[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_reo[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TX SW Pool
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_TX_DESC_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_tx_desc[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_txsw_pool[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng TX  EXt SW Pool
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_EXT_TX_DESC_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_ext_tx_desc[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_ext_txsw_pool[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng rxdma pool stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_RX_DESC_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_rx_desc[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_rxdma_pool[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Fillinng rxdma ring stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (j = 0; (j < NSS_STATS_WIFILI_RXDMA_DESC_MAX); j++) {
			stats_shadow[j] = nss_top_main.stats_wifili.stats_rxdma[i][j];
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_wifili_rxdma_ring[j], stats_shadow[j]);
		}

		spin_unlock_bh(&nss_top_main.stats_lock);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

	}

	/*
	 * Fillinng wbm ring stats
	 */
	spin_lock_bh(&nss_top_main.stats_lock);
	for (j = 0; (j < NSS_STATS_WIFILI_WBM_MAX); j++) {
		stats_shadow[j] = nss_top_main.stats_wifili.stats_wbm[j];
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"%s = %llu\n", nss_stats_str_wifili_wbm[j], stats_shadow[j]);
	}

	spin_unlock_bh(&nss_top_main.stats_lock);
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nwifili stats end\n\n");

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_dtls_read()
 *	Read DTLS session statistics
 */
static ssize_t nss_stats_dtls_read(struct file *fp, char __user *ubuf,
				   size_t sz, loff_t *ppos)
{
	uint32_t max_output_lines = 2 + (NSS_MAX_DTLS_SESSIONS
					* (NSS_STATS_DTLS_SESSION_MAX + 2)) + 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	int id, i;
	struct nss_stats_dtls_session_debug *dtls_session_stats = NULL;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	dtls_session_stats = kzalloc((sizeof(struct nss_stats_dtls_session_debug)
				     * NSS_MAX_DTLS_SESSIONS), GFP_KERNEL);
	if (unlikely(dtls_session_stats == NULL)) {
		nss_warning("Could not allocate memory for populating DTLS stats");
		kfree(lbuf);
		return 0;
	}

	/*
	 * Get all stats
	 */
	nss_dtls_session_debug_stats_get(dtls_session_stats);

	/*
	 * Session stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
			     "\nDTLS session stats start:\n\n");

	for (id = 0; id < NSS_MAX_DTLS_SESSIONS; id++) {
		if (!dtls_session_stats[id].valid)
			break;

		dev = dev_get_by_index(&init_net, dtls_session_stats[id].if_index);
		if (likely(dev)) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "%d. nss interface id=%d, netdevice=%s\n",
					     id, dtls_session_stats[id].if_num,
					     dev->name);
			dev_put(dev);
		} else {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "%d. nss interface id=%d\n", id,
					     dtls_session_stats[id].if_num);
		}

		for (i = 0; i < NSS_STATS_DTLS_SESSION_MAX; i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "\t%s = %llu\n",
					     nss_stats_str_dtls_session_debug_stats[i],
					     dtls_session_stats[id].stats[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
			     "\nDTLS session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(dtls_session_stats);
	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_gre_tunnel_read()
 *	Read GRE Tunnel session statistics
 */
static ssize_t nss_stats_gre_tunnel_read(struct file *fp, char __user *ubuf,
				   size_t sz, loff_t *ppos)
{
	uint32_t max_output_lines = 2 + (NSS_MAX_GRE_TUNNEL_SESSIONS
					* (NSS_STATS_GRE_TUNNEL_SESSION_MAX + 2)) + 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	int id, i;
	struct nss_stats_gre_tunnel_session_debug *gre_tunnel_session_stats = NULL;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	gre_tunnel_session_stats = kzalloc((sizeof(struct nss_stats_gre_tunnel_session_debug)
				     * NSS_MAX_GRE_TUNNEL_SESSIONS), GFP_KERNEL);
	if (unlikely(gre_tunnel_session_stats == NULL)) {
		nss_warning("Could not allocate memory for populating GRE Tunnel stats");
		kfree(lbuf);
		return 0;
	}

	/*
	 * Get all stats
	 */
	nss_gre_tunnel_session_debug_stats_get(gre_tunnel_session_stats);

	/*
	 * Session stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
			     "\nGRE Tunnel session stats start:\n\n");

	for (id = 0; id < NSS_MAX_GRE_TUNNEL_SESSIONS; id++) {
		if (!gre_tunnel_session_stats[id].valid)
			break;

		dev = dev_get_by_index(&init_net, gre_tunnel_session_stats[id].if_index);
		if (likely(dev)) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "%d. nss interface id=%d, netdevice=%s\n",
					     id, gre_tunnel_session_stats[id].if_num,
					     dev->name);
			dev_put(dev);
		} else {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "%d. nss interface id=%d\n", id,
					     gre_tunnel_session_stats[id].if_num);
		}

		for (i = 0; i < NSS_STATS_GRE_TUNNEL_SESSION_MAX; i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "\t%s = %llu\n",
					     nss_stats_str_gre_tunnel_session_debug_stats[i],
					     gre_tunnel_session_stats[id].stats[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
			     "\nGRE Tunnel session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(gre_tunnel_session_stats);
	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_l2tpv2_read()
 *	Read l2tpv2 statistics
 */
static ssize_t nss_stats_l2tpv2_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	uint32_t max_output_lines = 2 /* header & footer for session stats */
					+ NSS_MAX_L2TPV2_DYNAMIC_INTERFACES * (NSS_STATS_L2TPV2_SESSION_MAX + 2) /*session stats */
					+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines ;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	struct nss_stats_l2tpv2_session_debug l2tpv2_session_stats[NSS_MAX_L2TPV2_DYNAMIC_INTERFACES];
	int id, i;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(&l2tpv2_session_stats, 0, sizeof(struct nss_stats_l2tpv2_session_debug) * NSS_MAX_L2TPV2_DYNAMIC_INTERFACES);

	/*
	 * Get all stats
	 */
	nss_l2tpv2_session_debug_stats_get((void *)&l2tpv2_session_stats);

	/*
	 * Session stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nl2tp v2 session stats start:\n\n");
	for (id = 0; id < NSS_MAX_L2TPV2_DYNAMIC_INTERFACES; id++) {

			if (!l2tpv2_session_stats[id].valid) {
				break;
			}

			dev = dev_get_by_index(&init_net, l2tpv2_session_stats[id].if_index);
			if (likely(dev)) {

				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d, netdevice=%s\n", id,
						l2tpv2_session_stats[id].if_num, dev->name);
				dev_put(dev);
			} else {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d\n", id,
						l2tpv2_session_stats[id].if_num);
			}

			for (i = 0; i < NSS_STATS_L2TPV2_SESSION_MAX; i++) {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
						     "\t%s = %llu\n", nss_stats_str_l2tpv2_session_debug_stats[i],
						      l2tpv2_session_stats[id].stats[i]);
			}
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nl2tp v2 session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_map_t_read()
 *	Read map_t statistics
 */
static ssize_t nss_stats_map_t_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	uint32_t max_output_lines = 2 /* header & footer for instance stats */
					+ NSS_MAX_MAP_T_DYNAMIC_INTERFACES * (NSS_STATS_MAP_T_MAX + 2) /*instance stats */
					+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	struct nss_stats_map_t_instance_debug map_t_instance_stats[NSS_MAX_MAP_T_DYNAMIC_INTERFACES];
	int id, i;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(&map_t_instance_stats, 0, sizeof(struct nss_stats_map_t_instance_debug) * NSS_MAX_MAP_T_DYNAMIC_INTERFACES);

	/*
	 * Get all stats
	 */
	nss_map_t_instance_debug_stats_get((void *)&map_t_instance_stats);

	/*
	 * Session stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nmap_t instance stats start:\n\n");
	for (id = 0; id < NSS_MAX_MAP_T_DYNAMIC_INTERFACES; id++) {

			if (!map_t_instance_stats[id].valid) {
				break;
			}

			dev = dev_get_by_index(&init_net, map_t_instance_stats[id].if_index);
			if (likely(dev)) {

				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d, netdevice=%s\n", id,
						map_t_instance_stats[id].if_num, dev->name);
				dev_put(dev);
			} else {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d\n", id,
						map_t_instance_stats[id].if_num);
			}

			for (i = 0; i < NSS_STATS_MAP_T_MAX; i++) {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
						     "\t%s = %llu\n", nss_stats_str_map_t_instance_debug_stats[i],
						      map_t_instance_stats[id].stats[i]);
			}
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nmap_t instance stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

 /*
 * nss_stats_gre_read()
 *	Read GRE statistics
 */
static ssize_t nss_stats_gre_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t max_output_lines = 2 /* header & footer for base debug stats */
		+ 2 /* header & footer for session debug stats */
		+ NSS_STATS_GRE_BASE_DEBUG_MAX  /* Base debug */
		+ NSS_GRE_MAX_DEBUG_SESSION_STATS * (NSS_STATS_GRE_SESSION_DEBUG_MAX + 2) /*session stats */
		+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	struct nss_stats_gre_session_debug *sstats;
	struct nss_stats_gre_base_debug *bstats;
	int id, i;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	bstats = kzalloc(sizeof(struct nss_stats_gre_base_debug), GFP_KERNEL);
	if (unlikely(!bstats)) {
		nss_warning("Could not allocate memory for base debug statistics buffer");
		kfree(lbuf);
		return 0;
	}

	sstats = kzalloc(sizeof(struct nss_stats_gre_session_debug) * NSS_GRE_MAX_DEBUG_SESSION_STATS, GFP_KERNEL);
	if (unlikely(!sstats)) {
		nss_warning("Could not allocate memory for base debug statistics buffer");
		kfree(lbuf);
		kfree(bstats);
		return 0;
	}

	/*
	 * Get all base stats
	 */
	nss_gre_base_debug_stats_get((void *)bstats, sizeof(struct nss_stats_gre_base_debug));
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngre Base stats start:\n\n");
	for (i = 0; i < NSS_STATS_GRE_BASE_DEBUG_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				     "\t%s = %llu\n", nss_stats_str_gre_base_debug_stats[i],
				     bstats->stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngre Base stats End\n\n");

	/*
	 * Get all session stats
	 */
	nss_gre_session_debug_stats_get(sstats, sizeof(struct nss_stats_gre_session_debug) * NSS_GRE_MAX_DEBUG_SESSION_STATS);
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngre Session stats start:\n\n");

	for (id = 0; id < NSS_GRE_MAX_DEBUG_SESSION_STATS; id++) {

		if (!((sstats + id)->valid)) {
			continue;
		}

		dev = dev_get_by_index(&init_net, (sstats + id)->if_index);
		if (likely(dev)) {

			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d, netdevice=%s\n", id,
					     (sstats + id)->if_num, dev->name);
			dev_put(dev);
		} else {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d\n", id,
					     (sstats + id)->if_num);
		}

		for (i = 0; i < NSS_STATS_GRE_SESSION_DEBUG_MAX; i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					     "\t%s = %llu\n", nss_stats_str_gre_session_debug_stats[i],
					     (sstats + id)->stats[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngre Session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(sstats);
	kfree(bstats);
	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_ppe_conn_read()
 *	Read ppe connection stats
 */
static ssize_t nss_stats_ppe_conn_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	int i;
	char *lbuf = NULL;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint32_t ppe_stats[NSS_STATS_PPE_CONN_MAX];
	uint32_t max_output_lines = 2 /* header & footer for session stats */
				+ NSS_STATS_PPE_CONN_MAX /* PPE flow counters */
				+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;

	lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(&ppe_stats, 0, sizeof(uint32_t) * NSS_STATS_PPE_CONN_MAX);

	/*
	 * Get all stats
	 */
	nss_ppe_stats_conn_get(ppe_stats);

	/*
	 * flow stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe flow counters start:\n\n");

	for (i = 0; i < NSS_STATS_PPE_CONN_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_conn[i],
				ppe_stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe flow counters end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_ppe_l3_read()
 *	Read ppe L3 debug stats
 */
static ssize_t nss_stats_ppe_l3_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	int i;
	char *lbuf = NULL;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint32_t ppe_stats[NSS_STATS_PPE_L3_MAX];
	uint32_t max_output_lines = 2 /* header & footer for session stats */
				+ NSS_STATS_PPE_L3_MAX /* PPE flow counters */
				+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;

	lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(ppe_stats, 0, sizeof(uint32_t) * NSS_STATS_PPE_L3_MAX);

	/*
	 * Get all stats
	 */
	nss_ppe_stats_l3_get(ppe_stats);

	/*
	 * flow stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe l3 debug stats start:\n\n");

	for (i = 0; i < NSS_STATS_PPE_L3_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = 0x%x\n", nss_stats_str_ppe_l3[i],
				ppe_stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe l3 debug stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_ppe_code_read()
 *	Read ppe CPU & DROP code
 */
static ssize_t nss_stats_ppe_code_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	int i;
	char *lbuf = NULL;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint32_t ppe_stats[NSS_STATS_PPE_CODE_MAX];
	uint32_t max_output_lines = 2 /* header & footer for session stats */
				+ NSS_STATS_PPE_CODE_MAX /* PPE flow counters */
				+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;

	lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(ppe_stats, 0, sizeof(uint32_t) * NSS_STATS_PPE_CODE_MAX);

	/*
	 * Get all stats
	 */
	nss_ppe_stats_code_get(ppe_stats);

	/*
	 * flow stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe session stats start:\n\n");

	for (i = 0; i < NSS_STATS_PPE_CODE_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_code[i],
				ppe_stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_ppe_port_dc_read()
 *	Read PPE per port drop code stats
 */
static ssize_t nss_stats_ppe_port_dc_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + 2 start tag line + 2 end tag line + five blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_PPE_DROP_CODE_MAX + 4) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct nss_stats_data *data = fp->private_data;
	uint32_t *ppe_stats;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	ppe_stats = kzalloc(sizeof(uint32_t) * NSS_STATS_PPE_DROP_CODE_MAX, GFP_KERNEL);
	if (unlikely(ppe_stats == NULL)) {
		kfree(lbuf);
		nss_warning("Could not allocate memory for ppe stats buffer");
		return 0;
	}

	/*
	 * Get drop code counters for specific port
	 */
	nss_ppe_port_drop_code_get(ppe_stats, data->edma_id);
	size_wr = scnprintf(lbuf, size_al, "ppe no drop code stats start:\n\n");
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_dc[0],
				ppe_stats[0]);
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe no drop code stats end\n\n");

	/*
	 * Drop code stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "ppe non-zero drop code stats start:\n\n");
	for (i = 1; i < NSS_STATS_PPE_DROP_CODE_MAX; i++) {
		/*
		 * Print only non-zero stats.
		 */
		if (!ppe_stats[i]) {
			continue;
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_dc[i],
				ppe_stats[i]);
	}
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe non-zero drop code stats end\n\n");

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(ppe_stats);
	kfree(lbuf);

	return bytes_read;
}

/*
 * nss_stats_ppe_exception_cc_read()
 *	Read PPE CPU code stats specific to flow exceptions
 */
static ssize_t nss_stats_ppe_exception_cc_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_PPE_CPU_CODE_EXCEPTION_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint32_t *ppe_stats;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	ppe_stats = kzalloc(sizeof(uint32_t) * NSS_STATS_PPE_CPU_CODE_EXCEPTION_MAX, GFP_KERNEL);
	if (unlikely(ppe_stats == NULL)) {
		kfree(lbuf);
		nss_warning("Could not allocate memory for ppe stats buffer");
		return 0;
	}

	/*
	 * Get CPU code counters for flow specific exceptions
	 */
	nss_ppe_cpu_code_exception_get(ppe_stats);

	size_wr = scnprintf(lbuf, size_al, "ppe non-zero cpu code flow-exception stats start:\n\n");

	/*
	 * CPU code stats
	 */
	for (i = 0; i < NSS_STATS_PPE_CPU_CODE_EXCEPTION_MAX; i++) {
		/*
		 * Print only non-zero stats.
		 */
		if (!ppe_stats[i]) {
			continue;
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_cc[i],
				ppe_stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe non-zero cpu code flow-exception stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(ppe_stats);
	kfree(lbuf);

	return bytes_read;
}

/*
 * nss_stats_ppe_nonexception_cc_read()
 *	Read PPE CPU code stats for other than flow exceptions
 */
static ssize_t nss_stats_ppe_nonexception_cc_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint32_t *ppe_stats;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	ppe_stats = kzalloc(sizeof(uint32_t) * NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_MAX, GFP_KERNEL);
	if (unlikely(ppe_stats == NULL)) {
		kfree(lbuf);
		nss_warning("Could not allocate memory for ppe stats buffer");
		return 0;
	}

	/*
	 * Get CPU code counters for non flow exceptions
	 */
	nss_ppe_cpu_code_nonexception_get(ppe_stats);

	/*
	 * CPU code stats
	 */
	size_wr = scnprintf(lbuf, size_al, "ppe non-zero cpu code non-flow exception stats start:\n\n");
	for (i = 0; i < NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_MAX; i++) {
		/*
		 * Print only non-zero stats.
		 */
		if (!ppe_stats[i]) {
			continue;
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"\t%s = %u\n", nss_stats_str_ppe_cc[i + NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_START],
				ppe_stats[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nppe non-zero cpu code non-flow exception stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(ppe_stats);
	kfree(lbuf);

	return bytes_read;
}

/*
 * nss_stats_pptp_read()
 *	Read pptp statistics
 */
static ssize_t nss_stats_pptp_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{

	uint32_t max_output_lines = 2 /* header & footer for session stats */
					+ NSS_MAX_PPTP_DYNAMIC_INTERFACES * (NSS_STATS_PPTP_SESSION_MAX + 2) /*session stats */
					+ 2;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines ;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	struct net_device *dev;
	struct nss_stats_pptp_session_debug pptp_session_stats[NSS_MAX_PPTP_DYNAMIC_INTERFACES];
	int id, i;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	memset(&pptp_session_stats, 0, sizeof(struct nss_stats_pptp_session_debug) * NSS_MAX_PPTP_DYNAMIC_INTERFACES);

	/*
	 * Get all stats
	 */
	nss_pptp_session_debug_stats_get((void *)&pptp_session_stats);

	/*
	 * Session stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npptp session stats start:\n\n");
	for (id = 0; id < NSS_MAX_PPTP_DYNAMIC_INTERFACES; id++) {

			if (!pptp_session_stats[id].valid) {
				break;
			}

			dev = dev_get_by_index(&init_net, pptp_session_stats[id].if_index);
			if (likely(dev)) {

				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d, netdevice=%s\n", id,
						pptp_session_stats[id].if_num, dev->name);
				dev_put(dev);
			} else {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. nss interface id=%d\n", id,
						pptp_session_stats[id].if_num);
			}

			for (i = 0; i < NSS_STATS_PPTP_SESSION_MAX; i++) {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
						     "\t%s = %llu\n", nss_stats_str_pptp_session_debug_stats[i],
						      pptp_session_stats[id].stats[i]);
			}
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npptp session stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, size_wr);

	kfree(lbuf);
	return bytes_read;
}

/*
 * nss_stats_sjack_read()
 *	Read SJACK stats
 */
static ssize_t nss_stats_sjack_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_NODE_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_NODE_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "sjack stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_SJACK_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nsjack stats end\n\n");

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_portid_read()
 *	Read PortID stats
 */
static ssize_t nss_stats_portid_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_NODE_MAX + NSS_STATS_PORTID_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_NODE_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "portid stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_PORTID_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * PortID node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nportid node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_PORTID_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_portid[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_PORTID_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_portid[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nportid stats end\n\n");

	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_capwap_encap()
 *	Make a row for CAPWAP encap stats.
 */
static ssize_t nss_stats_capwap_encap(char *line, int len, int i, struct nss_capwap_tunnel_stats *s)
{
	char *header[] = { "packets", "bytes", "fragments", "drop_ref", "drop_ver", "drop_unalign",
			"drop_hroom", "drop_dtls", "drop_nwireless", "drop_qfull", "drop_memfail", "unknown" };
	uint64_t tcnt = 0;

	switch (i) {
	case 0:
		tcnt = s->pnode_stats.tx_packets;
		break;
	case 1:
		tcnt = s->pnode_stats.tx_bytes;
		break;
	case 2:
		tcnt = s->tx_segments;
		break;
	case 3:
		tcnt = s->tx_dropped_sg_ref;
		break;
	case 4:
		tcnt = s->tx_dropped_ver_mis;
		break;
	case 5:
		tcnt = s->tx_dropped_unalign;
		break;
	case 6:
		tcnt = s->tx_dropped_hroom;
		break;
	case 7:
		tcnt = s->tx_dropped_dtls;
		break;
	case 8:
		tcnt = s->tx_dropped_nwireless;
		break;
	case 9:
		tcnt = s->tx_queue_full_drops;
		break;
	case 10:
		tcnt = s->tx_mem_failure_drops;
		break;
	default:
		return 0;
	}

	return (snprintf(line, len, "%s = %llu\n", header[i], tcnt));
}

/*
 * nss_stats_capwap_decap()
 *	Make a row for CAPWAP decap stats.
 */
static ssize_t nss_stats_capwap_decap(char *line, int len, int i, struct nss_capwap_tunnel_stats *s)
{
	char *header[] = { "packets", "bytes", "DTLS_pkts", "fragments", "rx_dropped", "drop_oversize",
		"drop_frag_timeout", "drop_frag_dup", "drop_frag_gap", "drop_qfull", "drop_memfail",
		"drop_csum", "drop_malformed", "unknown" };
	uint64_t tcnt = 0;

	switch (i) {
	case 0:
		tcnt = s->pnode_stats.rx_packets;
		break;
	case 1:
		tcnt = s->pnode_stats.rx_bytes;
		break;
	case 2:
		tcnt = s->dtls_pkts;
		break;
	case 3:
		tcnt = s->rx_segments;
		break;
	case 4:
		tcnt = s->pnode_stats.rx_dropped;
		break;
	case 5:
		tcnt = s->rx_oversize_drops;
		break;
	case 6:
		tcnt = s->rx_frag_timeout_drops;
		break;
	case 7:
		tcnt = s->rx_dup_frag;
		break;
	case 8:
		tcnt = s->rx_frag_gap_drops;
		break;
	case 9:
		tcnt = s->rx_queue_full_drops;
		return (snprintf(line, len, "%s = %llu (n2h = %llu)\n", header[i], tcnt, s->rx_n2h_queue_full_drops));
	case 10:
		tcnt = s->rx_mem_failure_drops;
		break;
	case 11:
		tcnt = s->rx_csum_drops;
		break;
	case 12:
		tcnt = s->rx_malformed;
		break;
	default:
		return 0;
	}

	return (snprintf(line, len, "%s = %llu\n", header[i], tcnt));
}

/*
 * nss_stats_capwap_read()
 *	Read CAPWAP stats
 */
static ssize_t nss_stats_capwap_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos, uint16_t type)
{
	struct nss_stats_data *data = fp->private_data;
	ssize_t bytes_read = 0;
	struct nss_capwap_tunnel_stats stats;
	size_t bytes;
	char line[80];
	int start;
	uint32_t if_num = NSS_DYNAMIC_IF_START;
	uint32_t max_if_num = NSS_DYNAMIC_IF_START + NSS_MAX_DYNAMIC_INTERFACES;

	if (data) {
		if_num = data->if_num;
	}

	/*
	 * If we are done accomodating all the CAPWAP tunnels.
	 */
	if (if_num > max_if_num) {
		return 0;
	}

	for (; if_num <= max_if_num; if_num++) {
		bool isthere;

		if (nss_is_dynamic_interface(if_num) == false) {
			continue;
		}

		if (nss_dynamic_interface_get_type(nss_capwap_get_ctx(), if_num) != NSS_DYNAMIC_INTERFACE_TYPE_CAPWAP) {
			continue;
		}

		/*
		 * If CAPWAP tunnel does not exists, then isthere will be false.
		 */
		isthere = nss_capwap_get_stats(if_num, &stats);
		if (!isthere) {
			continue;
		}

		bytes = snprintf(line, sizeof(line), "----if_num : %2d----\n", if_num);
		if ((bytes_read + bytes) > sz) {
			break;
		}

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto fail;
		}
		bytes_read += bytes;
		start = 0;
		while (bytes_read < sz) {
			if (type == 1) {
				bytes = nss_stats_capwap_encap(line, sizeof(line), start, &stats);
			} else {
				bytes = nss_stats_capwap_decap(line, sizeof(line), start, &stats);
			}

			/*
			 * If we don't have any more lines in decap/encap.
			 */
			if (bytes == 0) {
				break;
			}

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto fail;
			}

			bytes_read += bytes;
			start++;
		}
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->if_num = if_num;
	}
fail:
	return bytes_read;
}

/*
 * nss_stats_capwap_decap_read()
 *	Read CAPWAP decap stats
 */
static ssize_t nss_stats_capwap_decap_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return (nss_stats_capwap_read(fp, ubuf, sz, ppos, 0));
}

/*
 * nss_stats_capwap_encap_read()
 *	Read CAPWAP encap stats
 */
static ssize_t nss_stats_capwap_encap_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	return (nss_stats_capwap_read(fp, ubuf, sz, ppos, 1));
}

/*
 * nss_stats_gre_redir()
 *	Make a row for GRE_REDIR stats.
 */
static ssize_t nss_stats_gre_redir(char *line, int len, int i, struct nss_gre_redir_tunnel_stats *s)
{
	char *header[] = { "TX Packets", "TX Bytes", "TX Drops", "RX Packets", "RX Bytes", "Rx Drops" };
	uint64_t tcnt = 0;

	switch (i) {
	case 0:
		tcnt = s->node_stats.tx_packets;
		break;
	case 1:
		tcnt = s->node_stats.tx_bytes;
		break;
	case 2:
		tcnt = s->tx_dropped;
		break;
	case 3:
		tcnt = s->node_stats.rx_packets;
		break;
	case 4:
		tcnt = s->node_stats.rx_bytes;
		break;
	case 5:
		tcnt = s->node_stats.rx_dropped;
		break;
	default:
		return 0;
	}

	return (snprintf(line, len, "%s = %llu\n", header[i], tcnt));
}

/*
 * nss_stats_gre_redir_read()
 *	READ gre_redir tunnel stats.
 */
static ssize_t nss_stats_gre_redir_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	ssize_t bytes_read = 0;
	struct nss_gre_redir_tunnel_stats stats;
	size_t bytes;
	char line[80];
	int start, end;
	int index = 0;

	if (data) {
		index = data->index;
	}

	/*
	 * If we are done accomodating all the GRE_REDIR tunnels.
	 */
	if (index >= NSS_GRE_REDIR_MAX_INTERFACES) {
		return 0;
	}

	for (; index < NSS_GRE_REDIR_MAX_INTERFACES; index++) {
		bool isthere;

		/*
		 * If gre_redir tunnel does not exists, then isthere will be false.
		 */
		isthere = nss_gre_redir_get_stats(index, &stats);
		if (!isthere) {
			continue;
		}

		bytes = snprintf(line, sizeof(line), "\nTunnel if_num: %2d\n", stats.if_num);
		if ((bytes_read + bytes) > sz) {
			break;
		}

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto fail;
		}
		bytes_read += bytes;
		start = 0;
		end = 6;
		while (bytes_read < sz && start < end) {
			bytes = nss_stats_gre_redir(line, sizeof(line), start, &stats);

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto fail;
			}

			bytes_read += bytes;
			start++;
		}
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->index = index;
	}

fail:
	return bytes_read;
}

/*
 * nss_stats_wifi_if_read()
 *	Read wifi_if statistics
 */
static ssize_t nss_stats_wifi_if_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.wifi_handler_id];
	int32_t if_num = NSS_DYNAMIC_IF_START;
	int32_t max_if_num = if_num + NSS_MAX_DYNAMIC_INTERFACES;
	size_t bytes = 0;
	ssize_t bytes_read = 0;
	char line[80];
	int start, end;

	if (data) {
		if_num = data->if_num;
	}

	if (if_num > max_if_num) {
		return 0;
	}

	for (; if_num < max_if_num; if_num++) {
		if (nss_dynamic_interface_get_type(nss_ctx, if_num) != NSS_DYNAMIC_INTERFACE_TYPE_WIFI)
			continue;

		bytes = scnprintf(line, sizeof(line), "if_num %d stats start:\n\n", if_num);
		if ((bytes_read + bytes) > sz)
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;

		start = 0;
		end = 7;
		while (bytes_read < sz && start < end) {
			bytes = nss_wifi_if_copy_stats(if_num, start, line);
			if (!bytes)
				break;

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto end;
			}

			bytes_read += bytes;
			start++;
		}

		bytes = scnprintf(line, sizeof(line), "if_num %d stats end:\n\n", if_num);
		if (bytes_read > (sz - bytes))
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->if_num = if_num;
	}

end:
	return bytes_read;
}

/*
 * nss_stats_virt_if_read()
 *	Read virt_if statistics
 */
static ssize_t nss_stats_virt_if_read(struct file *fp, char __user *ubuf,
						size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.wifi_handler_id];
	int32_t if_num = NSS_DYNAMIC_IF_START;
	int32_t max_if_num = if_num + NSS_MAX_DYNAMIC_INTERFACES;
	size_t bytes = 0;
	ssize_t bytes_read = 0;
	char line[80];
	int start, end;

	if (data) {
		if_num = data->if_num;
	}

	if (if_num > max_if_num) {
		return 0;
	}

	for (; if_num < max_if_num; if_num++) {
		if (nss_dynamic_interface_get_type(nss_ctx, if_num) != NSS_DYNAMIC_INTERFACE_TYPE_802_3_REDIR)
			continue;

		bytes = scnprintf(line, sizeof(line), "if_num %d stats start:\n\n", if_num);
		if ((bytes_read + bytes) > sz)
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;

		start = 0;
		end = 7;
		while (bytes_read < sz && start < end) {
			bytes = nss_virt_if_copy_stats(if_num, start, line);
			if (!bytes)
				break;

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto end;
			}

			bytes_read += bytes;
			start++;
		}

		bytes = scnprintf(line, sizeof(line), "if_num %d stats end:\n\n", if_num);
		if (bytes_read > (sz - bytes))
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->if_num = if_num;
	}

end:
	return bytes_read;
}

/*
 * nss_stats_tx_rx_virt_if_read()
 *	Read tx_rx_virt_if statistics
 */
static ssize_t nss_stats_tx_rx_virt_if_read(struct file *fp, char __user *ubuf,
						size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)&nss_top_main.nss[nss_top_main.wifi_handler_id];
	int32_t if_num = NSS_DYNAMIC_IF_START;
	int32_t max_if_num = if_num + NSS_MAX_DYNAMIC_INTERFACES;
	size_t bytes = 0;
	ssize_t bytes_read = 0;
	char line[80];
	int start, end;

	if (data) {
		if_num = data->if_num;
	}

	if (if_num > max_if_num) {
		return 0;
	}

	for (; if_num < max_if_num; if_num++) {
		if (nss_dynamic_interface_get_type(nss_ctx, if_num) != NSS_DYNAMIC_INTERFACE_TYPE_VIRTIF_DEPRECATED)
			continue;

		bytes = scnprintf(line, sizeof(line), "if_num %d stats start:\n\n", if_num);
		if ((bytes_read + bytes) > sz)
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;

		start = 0;
		end = 7;
		while (bytes_read < sz && start < end) {
			bytes = nss_tx_rx_virt_if_copy_stats(if_num, start, line);
			if (!bytes)
				break;

			if ((bytes_read + bytes) > sz)
				break;

			if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
				bytes_read = -EFAULT;
				goto end;
			}

			bytes_read += bytes;
			start++;
		}

		bytes = scnprintf(line, sizeof(line), "if_num %d stats end:\n\n", if_num);
		if (bytes_read > (sz - bytes))
			break;

		if (copy_to_user(ubuf + bytes_read, line, bytes) != 0) {
			bytes_read = -EFAULT;
			goto end;
		}

		bytes_read += bytes;
	}

	if (bytes_read > 0) {
		*ppos = bytes_read;
	}

	if (data) {
		data->if_num = if_num;
	}

end:
	return bytes_read;
}

/*
 * nss_stats_trustsec_tx_read()
 *	Read trustsec_tx stats
 */
static ssize_t nss_stats_trustsec_tx_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + (NSS_STATS_TRUSTSEC_TX_MAX + 3) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_NODE_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "trustsec_tx stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "common node stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_node[NSS_TRUSTSEC_TX_INTERFACE][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_node[i], stats_shadow[i]);
	}

	/*
	 * TrustSec TX node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ntrustsec tx node stats:\n\n");

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_TRUSTSEC_TX_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_trustsec_tx[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_TRUSTSEC_TX_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_trustsec_tx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ntrustsec tx stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_wt_read()
 *	Reads and formats worker thread statistics and outputs them to ubuf
 */
static ssize_t nss_stats_wt_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	struct nss_stats_data *data = fp->private_data;
	struct nss_ctx_instance *nss_ctx = data->nss_ctx;
	struct nss_project_irq_stats *shadow;
	uint32_t thread_count = nss_ctx->worker_thread_count;
	uint32_t irq_count = nss_ctx->irq_count;

	/*
	 * Three lines for each IRQ
	 */
	uint32_t max_output_lines = thread_count * 3 * irq_count;
	size_t size_al = max_output_lines * NSS_STATS_MAX_STR_LENGTH;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	char *lbuf;
	int i;
	int j;

	lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(!lbuf)) {
		nss_warning("Could not allocate memory for local statistics buffer\n");
		return 0;
	}

	shadow = kzalloc(thread_count * irq_count * sizeof(struct nss_project_irq_stats), GFP_KERNEL);
	if (unlikely(!shadow)) {
		nss_warning("Could not allocate memory for stats shadow\n");
		kfree(lbuf);
		return 0;
	}

	spin_lock_bh(&nss_top_main.stats_lock);
	if (unlikely(!nss_ctx->wt_stats)) {
		spin_unlock_bh(&nss_top_main.stats_lock);
		nss_warning("Worker thread statistics not allocated\n");
		kfree(lbuf);
		kfree(shadow);
		return 0;
	}
	for (i = 0; i < thread_count; ++i) {

		/*
		 * The statistics shadow is an array with thread_count * irq_count
		 * items in it. Each item is located at the index:
		 *	(thread number) * (irq_count) + (irq number)
		 * thus simulating a two-dimensional array.
		 */
		for (j = 0; j < irq_count; ++j) {
			shadow[i * irq_count + j] = nss_ctx->wt_stats[i].irq_stats[j];
		}
	}
	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < thread_count; ++i) {
		for (j = 0; j < irq_count; ++j) {
			struct nss_project_irq_stats *is = &(shadow[i * irq_count + j]);
			if (!(is->count)) {
				continue;
			}

			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d callback: 0x%x, count: %llu\n",
				i, j, is->callback, is->count);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d tick min: %10u  avg: %10u  max:%10u\n",
				i, j, is->ticks_min, is->ticks_avg, is->ticks_max);
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
				"t-%d:irq-%d insn min: %10u  avg: %10u  max:%10u\n\n",
				i, j, is->insn_min, is->insn_avg, is->insn_max);
		}
	}
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(shadow);

	return bytes_read;
}

/*
 * nss_stats_open()
 */
static int nss_stats_open(struct inode *inode, struct file *filp)
{
	struct nss_stats_data *data = NULL;

	data = kzalloc(sizeof(struct nss_stats_data), GFP_KERNEL);
	if (!data) {
		return -ENOMEM;
	}
	memset(data, 0, sizeof (struct nss_stats_data));
	data->if_num = NSS_DYNAMIC_IF_START;
	data->index = 0;
	data->edma_id = (nss_ptr_t)inode->i_private;
	data->nss_ctx = (struct nss_ctx_instance *)(inode->i_private);
	filp->private_data = data;

	return 0;
}

/*
 * nss_stats_release()
 */
static int nss_stats_release(struct inode *inode, struct file *filp)
{
	struct nss_stats_data *data = filp->private_data;

	if (data) {
		kfree(data);
	}

	return 0;
}

#define NSS_STATS_DECLARE_FILE_OPERATIONS(name) \
static const struct file_operations nss_stats_##name##_ops = { \
	.open = nss_stats_open, \
	.read = nss_stats_##name##_read, \
	.llseek = generic_file_llseek, \
	.release = nss_stats_release, \
};

/*
 * nss_ipv4_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv4)

/*
 * ipv4_reasm_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv4_reasm)

/*
 * ipv6_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv6)

/*
 * ipv6_reasm_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv6_reasm)

/*
 * n2h_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(n2h)

/*
 * lso_rx_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(lso_rx)

/*
 * drv_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(drv)

/*
 * pppoe_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(pppoe)

/*
 * l2tpv2_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(l2tpv2)

/*
 * map_t_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(map_t)

/*
 * gre_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gre)

/*
 * ppe_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_conn)
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_l3)
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_code)
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_port_dc)
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_exception_cc)
NSS_STATS_DECLARE_FILE_OPERATIONS(ppe_nonexception_cc)

/*
 * pptp_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(pptp)

/*
 * gmac_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gmac)

/*
 * capwap_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(capwap_encap)
NSS_STATS_DECLARE_FILE_OPERATIONS(capwap_decap)

/*
 * eth_rx_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(eth_rx)

/*
 * edma_port_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port_stats)

/*
 * edma_port_type_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port_type)

/*
 * edma_port_ring_map_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port_ring_map)

/*
 * edma_txring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_txring)

/*
 * edma_rxring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_rxring)

/*
 * edma_txcmplring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_txcmplring)

/*
 * edma_rxfillring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_rxfillring)

/*
 * edma_err_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_err_stats)

/*
 * gre_redir_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gre_redir)

/*
 * sjack_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(sjack)

/*
 * portid_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(portid)

NSS_STATS_DECLARE_FILE_OPERATIONS(wifi_if)

NSS_STATS_DECLARE_FILE_OPERATIONS(virt_if)

NSS_STATS_DECLARE_FILE_OPERATIONS(tx_rx_virt_if)

/*
 * wifi_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(wifi)

/*
 * dtls_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(dtls)

/*
 * gre_tunnel_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gre_tunnel)

/*
 * trustsec_tx_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(trustsec_tx)

/*
 * wifili_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(wifili)

/*
 * wt_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(wt)
/*
 * nss_stats_init()
 * 	Enable NSS statistics
 */
void nss_stats_init(void)
{
	int i = 0;
	struct dentry *edma_d = NULL;
	struct dentry *edma_port_dir_d = NULL;
	struct dentry *edma_port_d = NULL;
	struct dentry *edma_port_type_d = NULL;
	struct dentry *edma_port_stats_d = NULL;
	struct dentry *edma_port_ring_map_d = NULL;
	struct dentry *edma_rings_dir_d = NULL;
	struct dentry *edma_tx_dir_d = NULL;
	struct dentry *edma_tx_d = NULL;
	struct dentry *edma_rx_dir_d = NULL;
	struct dentry *edma_rx_d = NULL;
	struct dentry *edma_txcmpl_dir_d = NULL;
	struct dentry *edma_txcmpl_d = NULL;
	struct dentry *edma_rxfill_dir_d = NULL;
	struct dentry *edma_rxfill_d = NULL;
	struct dentry *edma_err_stats_d = NULL;

	struct dentry *ppe_code_d = NULL;
	struct dentry *ppe_drop_d = NULL;
	struct dentry *ppe_port_dc_d = NULL;
	struct dentry *ppe_cpu_d = NULL;
	struct dentry *ppe_exception_d = NULL;
	struct dentry *ppe_nonexception_d = NULL;
	struct dentry *core_dentry = NULL;
	struct dentry *wt_dentry = NULL;


	char file_name[10];

	/*
	 * NSS driver entry
	 */
	nss_top_main.top_dentry = debugfs_create_dir("qca-nss-drv", NULL);
	if (unlikely(nss_top_main.top_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv directory in debugfs");

		/*
		 * Non availability of debugfs directory is not a catastrophy
		 * We can still go ahead with other initialization
		 */
		return;
	}

	nss_top_main.stats_dentry = debugfs_create_dir("stats", nss_top_main.top_dentry);
	if (unlikely(nss_top_main.stats_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv directory in debugfs");

		/*
		 * Non availability of debugfs directory is not a catastrophy
		 * We can still go ahead with rest of initialization
		 */
		return;
	}

	/*
	 * Create files to obtain statistics
	 */

	/*
	 * ipv4_stats
	 */
	nss_top_main.ipv4_dentry = debugfs_create_file("ipv4", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv4_ops);
	if (unlikely(nss_top_main.ipv4_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv4 file in debugfs");
		return;
	}

	/*
	 * ipv4_reasm_stats
	 */
	nss_top_main.ipv4_reasm_dentry = debugfs_create_file("ipv4_reasm", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv4_reasm_ops);
	if (unlikely(nss_top_main.ipv4_reasm_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv4_reasm file in debugfs");
		return;
	}

	/*
	 * ipv6_stats
	 */
	nss_top_main.ipv6_dentry = debugfs_create_file("ipv6", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv6_ops);
	if (unlikely(nss_top_main.ipv6_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv6 file in debugfs");
		return;
	}

	/*
	 * ipv6_reasm_stats
	 */
	nss_top_main.ipv6_reasm_dentry = debugfs_create_file("ipv6_reasm", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv6_reasm_ops);
	if (unlikely(nss_top_main.ipv6_reasm_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv6_reasm file in debugfs");
		return;
	}

	/*
	 * eth_rx__stats
	 */
	nss_top_main.eth_rx_dentry = debugfs_create_file("eth_rx", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_eth_rx_ops);
	if (unlikely(nss_top_main.eth_rx_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/eth_rx file in debugfs");
		return;
	}

	/*
	 * edma stats
	 */
	edma_d = debugfs_create_dir("edma", nss_top_main.stats_dentry);
	if (unlikely(edma_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma directory in debugfs");
		return;
	}

	/*
	 * edma port stats
	 */
	edma_port_dir_d = debugfs_create_dir("ports", edma_d);
	if (unlikely(edma_port_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/ports directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_PORTS_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		snprintf(file_name, sizeof(file_name), "%d", i);
		edma_port_d  = NULL;
		edma_port_stats_d = NULL;
		edma_port_type_d = NULL;
		edma_port_ring_map_d = NULL;

		edma_port_d = debugfs_create_dir(file_name, edma_port_dir_d);
		if (unlikely(edma_port_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d dir in debugfs", i);
			return;
		}

		edma_port_stats_d = debugfs_create_file("stats", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_stats_edma_port_stats_ops);
		if (unlikely(edma_port_stats_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/stats file in debugfs", i);
			return;
		}

		edma_port_type_d = debugfs_create_file("type", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_stats_edma_port_type_ops);
		if (unlikely(edma_port_type_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/type file in debugfs", i);
			return;
		}

		edma_port_ring_map_d = debugfs_create_file("ring_map", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_stats_edma_port_ring_map_ops);
		if (unlikely(edma_port_ring_map_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/ring_map file in debugfs", i);
			return;
		}
	}

	/*
	 *  edma error stats
	 */
	edma_err_stats_d = NULL;
	edma_err_stats_d = debugfs_create_file("err_stats", 0400, edma_d, &nss_top_main, &nss_stats_edma_err_stats_ops);
	if (unlikely(edma_port_stats_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/%d/err_stats file in debugfs", 0);
		return;
	}

	/*
	 * edma ring stats
	 */
	edma_rings_dir_d = debugfs_create_dir("rings", edma_d);
	if (unlikely(edma_rings_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings directory in debugfs");
		return;
	}

	/*
	 * edma tx ring stats
	 */
	edma_tx_dir_d = debugfs_create_dir("tx", edma_rings_dir_d);
	if (unlikely(edma_tx_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/tx directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_TX_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_tx_d = NULL;
		edma_tx_d = debugfs_create_file(file_name, 0400, edma_tx_dir_d, (void *)(nss_ptr_t)i, &nss_stats_edma_txring_ops);
		if (unlikely(edma_tx_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/tx/%d file in debugfs", i);
			return;
		}
	}

	/*
	 * edma rx ring stats
	 */
	edma_rx_dir_d = debugfs_create_dir("rx", edma_rings_dir_d);
	if (unlikely(edma_rx_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rx directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_RX_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_rx_d = NULL;
		edma_rx_d = debugfs_create_file(file_name, 0400, edma_rx_dir_d, (void *)(nss_ptr_t)i, &nss_stats_edma_rxring_ops);
		if (unlikely(edma_rx_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rx/%d file in debugfs", i);
			return;
		}
	}

	/*
	 * edma tx cmpl ring stats
	 */
	edma_txcmpl_dir_d = debugfs_create_dir("txcmpl", edma_rings_dir_d);
	if (unlikely(edma_txcmpl_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/txcmpl directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_TXCMPL_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_txcmpl_d = NULL;
		edma_txcmpl_d = debugfs_create_file(file_name, 0400, edma_txcmpl_dir_d, (void *)(nss_ptr_t)i, &nss_stats_edma_txcmplring_ops);
		if (unlikely(edma_txcmpl_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/txcmpl/%d file in debugfs", i);
			return;
		}
	}

	/*
	 * edma rx fill ring stats
	 */
	edma_rxfill_dir_d = debugfs_create_dir("rxfill", edma_rings_dir_d);
	if (unlikely(edma_rxfill_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rxfill directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_RXFILL_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_rxfill_d = NULL;
		edma_rxfill_d = debugfs_create_file(file_name, 0400, edma_rxfill_dir_d, (void *)(nss_ptr_t)i, &nss_stats_edma_rxfillring_ops);
		if (unlikely(edma_rxfill_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rxfill/%d file in debugfs", i);
			return;
		}
	}

	/*
	 * n2h_stats
	 */
	nss_top_main.n2h_dentry = debugfs_create_file("n2h", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_n2h_ops);
	if (unlikely(nss_top_main.n2h_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/n2h directory in debugfs");
		return;
	}

	/*
	 * lso_rx_stats
	 */
	nss_top_main.lso_rx_dentry = debugfs_create_file("lso_rx", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_lso_rx_ops);
	if (unlikely(nss_top_main.lso_rx_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/lso_rx file in debugfs");
		return;
	}

	/*
	 * drv_stats
	 */
	nss_top_main.drv_dentry = debugfs_create_file("drv", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_drv_ops);
	if (unlikely(nss_top_main.drv_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/drv directory in debugfs");
		return;
	}

	/*
	 * pppoe_stats
	 */
	nss_top_main.pppoe_dentry = debugfs_create_file("pppoe", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_pppoe_ops);
	if (unlikely(nss_top_main.pppoe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/pppoe file in debugfs");
		return;
	}

	/*
	 * gmac_stats
	 */
	nss_top_main.gmac_dentry = debugfs_create_file("gmac", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_gmac_ops);
	if (unlikely(nss_top_main.gmac_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/gmac file in debugfs");
		return;
	}

	/*
	 * CAPWAP stats.
	 */
	nss_top_main.capwap_encap_dentry = debugfs_create_file("capwap_encap", 0400,
	nss_top_main.stats_dentry, &nss_top_main, &nss_stats_capwap_encap_ops);
	if (unlikely(nss_top_main.capwap_encap_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/capwap_encap file in debugfs");
		return;
	}

	nss_top_main.capwap_decap_dentry = debugfs_create_file("capwap_decap", 0400,
	nss_top_main.stats_dentry, &nss_top_main, &nss_stats_capwap_decap_ops);
	if (unlikely(nss_top_main.capwap_decap_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/capwap_decap file in debugfs");
		return;
	}

	/*
	 * GRE_REDIR stats
	 */
	nss_top_main.gre_redir_dentry = debugfs_create_file("gre_redir", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_gre_redir_ops);
	if (unlikely(nss_top_main.gre_redir_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/gre_redir file in debugfs");
		return;
	}

	/*
	 * SJACK stats
	 */
	nss_top_main.sjack_dentry = debugfs_create_file("sjack", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_sjack_ops);
	if (unlikely(nss_top_main.sjack_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/sjack file in debugfs");
		return;
	}

	/*
	 * PORTID stats
	 */
	nss_top_main.portid_dentry = debugfs_create_file("portid", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_portid_ops);
	if (unlikely(nss_top_main.portid_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/portid file in debugfs");
		return;
	}

	/*
	 * WIFI stats
	 */
	nss_top_main.wifi_dentry = debugfs_create_file("wifi", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_wifi_ops);
	if (unlikely(nss_top_main.wifi_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi file in debugfs");
		return;
	}

	/*
	 * wifi_if stats
	 */
	nss_top_main.wifi_if_dentry = debugfs_create_file("wifi_if", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_wifi_if_ops);
	if (unlikely(nss_top_main.wifi_if_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/wifi_if file in debugfs");
		return;
	}

	nss_top_main.virt_if_dentry = debugfs_create_file("virt_if", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_virt_if_ops);
	if (unlikely(nss_top_main.virt_if_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/virt_if file in debugfs");
		return;
	}

	nss_top_main.tx_rx_virt_if_dentry = debugfs_create_file("tx_rx_virt_if", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_tx_rx_virt_if_ops);
	if (unlikely(nss_top_main.virt_if_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/tx_rx_virt_if file in debugfs");
		return;
	}

	/*
	 *  L2TPV2 Stats
	 */
	nss_top_main.l2tpv2_dentry = debugfs_create_file("l2tpv2", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_l2tpv2_ops);
	if (unlikely(nss_top_main.l2tpv2_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/l2tpv2 file in debugfs");
		return;
	}

	/*
	 *  Map-t Stats
	 */
	nss_top_main.map_t_dentry = debugfs_create_file("map_t", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_map_t_ops);
	if (unlikely(nss_top_main.map_t_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/map_t file in debugfs");
		return;
	}

	/*
	 *  GRE statistics
	 */
	nss_top_main.gre_dentry = debugfs_create_file("gre", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_gre_ops);
	if (unlikely(nss_top_main.gre_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/gre file in debugfs");
		return;
	}

	/*
	 *  PPE Stats
	 */
	nss_top_main.ppe_dentry = debugfs_create_dir("ppe", nss_top_main.stats_dentry);
	if (unlikely(nss_top_main.ppe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv directory in debugfs");
		return;
	}

	nss_top_main.ppe_conn_dentry = debugfs_create_file("connection", 0400,
						nss_top_main.ppe_dentry, &nss_top_main, &nss_stats_ppe_conn_ops);
	if (unlikely(nss_top_main.ppe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/connection file in debugfs");
	}

	nss_top_main.ppe_l3_dentry = debugfs_create_file("l3", 0400,
						nss_top_main.ppe_dentry, &nss_top_main, &nss_stats_ppe_l3_ops);
	if (unlikely(nss_top_main.ppe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/l3 file in debugfs");
	}

	nss_top_main.ppe_l3_dentry = debugfs_create_file("ppe_code", 0400,
						nss_top_main.ppe_dentry, &nss_top_main, &nss_stats_ppe_code_ops);
	if (unlikely(nss_top_main.ppe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/ppe_code file in debugfs");
	}

	/*
	 * ppe exception and drop code stats
	 */
	ppe_code_d = debugfs_create_dir("code", nss_top_main.ppe_dentry);
	if (unlikely(ppe_code_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/code directory in debugfs");
		return;
	}

	ppe_cpu_d = debugfs_create_dir("cpu", ppe_code_d);
	if (unlikely(ppe_cpu_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/code/cpu directory in debugfs");
		return;
	}

	ppe_exception_d = debugfs_create_file("exception", 0400, ppe_cpu_d,
			&nss_top_main, &nss_stats_ppe_exception_cc_ops);
	if (unlikely(ppe_exception_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/code/exception file in debugfs");
		return;
	}

	ppe_nonexception_d = debugfs_create_file("non-exception", 0400, ppe_cpu_d,
			&nss_top_main, &nss_stats_ppe_nonexception_cc_ops);
	if (unlikely(ppe_nonexception_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/code/non-exception file in debugfs");
		return;
	}

	ppe_drop_d = debugfs_create_dir("drop", ppe_code_d);
	if (unlikely(ppe_drop_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ppe/code/drop directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_PPE_NUM_PHY_PORTS_MAX; i++) {
		if (i > 0) {
			memset(file_name, 0, sizeof(file_name));
			snprintf(file_name, sizeof(file_name), "%d", i);
		}

		ppe_port_dc_d  = NULL;
		ppe_port_dc_d = debugfs_create_file((i == 0) ? "cpu" : file_name, 0400, ppe_drop_d,
					(void *)(nss_ptr_t)i, &nss_stats_ppe_port_dc_ops);
		if (unlikely(ppe_port_dc_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/ppe/code/drop/%d file in debugfs", i);
			return;
		}
	}

	/*
	 *  PPTP Stats
	 */
	nss_top_main.pptp_dentry = debugfs_create_file("pptp", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_pptp_ops);
	if (unlikely(nss_top_main.pptp_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/pptp file in debugfs");
	}

	/*
	 *  DTLS Stats
	 */
	nss_top_main.dtls_dentry = debugfs_create_file("dtls", 0400,
							nss_top_main.stats_dentry,
							&nss_top_main,
							&nss_stats_dtls_ops);
	if (unlikely(nss_top_main.dtls_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/dtls file in debugfs");
		return;
	}

	/*
	 *  GRE Tunnel Stats
	 */
	nss_top_main.gre_tunnel_dentry = debugfs_create_file("gre_tunnel", 0400,
							nss_top_main.stats_dentry,
							&nss_top_main,
							&nss_stats_gre_tunnel_ops);
	if (unlikely(nss_top_main.gre_tunnel_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/gre_tunnel file in debugfs");
		return;
	}

	/*
	 * TrustSec TX Stats
	 */
	nss_top_main.trustsec_tx_dentry = debugfs_create_file("trustsec_tx", 0400,
							nss_top_main.stats_dentry,
							&nss_top_main,
							&nss_stats_trustsec_tx_ops);
	if (unlikely(nss_top_main.trustsec_tx_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/trustsec_tx file in debugfs");
		return;
	}

	/*
	 * WIFILI stats
	 */
	nss_top_main.wifili_dentry = debugfs_create_file("wifili", 0400,
						nss_top_main.stats_dentry,
						&nss_top_main, &nss_stats_wifili_ops);
	if (unlikely(nss_top_main.wifili_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/wifili file in debugfs");
		return;
	}

	/*
	 * Per-project stats
	 */
	nss_top_main.project_dentry = debugfs_create_dir("project",
						nss_top_main.stats_dentry);
	if (unlikely(nss_top_main.project_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/project directory in debugfs");
		return;
	}

	for (i = 0; i < NSS_MAX_CORES; ++i) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "core%d", i);
		core_dentry = debugfs_create_dir(file_name,
						nss_top_main.project_dentry);
		if (unlikely(core_dentry == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/project/core%d directory in debugfs", i);
			return;
		}

		wt_dentry = debugfs_create_file("worker_threads",
						0400,
						core_dentry,
						&(nss_top_main.nss[i]),
						&nss_stats_wt_ops);
		if (unlikely(wt_dentry == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/project/core%d/worker_threads file in debugfs", i);
			return;
		}
	}

	nss_log_init();
}

/*
 * nss_stats_clean()
 * 	Cleanup NSS statistics files
 */
void nss_stats_clean(void)
{
	/*
	 * Remove debugfs tree
	 */
	if (likely(nss_top_main.top_dentry != NULL)) {
		debugfs_remove_recursive(nss_top_main.top_dentry);
		nss_top_main.top_dentry = NULL;
	}
}

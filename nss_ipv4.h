/*
 **************************************************************************
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
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
 * nss_ipv4.h
 *	NSS to HLOS interface definitions.
 */

/*
 * TODO: Since this is the now the public header file for writting an
 * IPv4 message, we need to convert the entire file to doxygen.
 */

#ifndef __NSS_IPV4_H
#define __NSS_IPV4_H

/*
 * IPv4 bridge/route rule messages
 */

enum nss_ipv4_message_types {
	NSS_IPV4_TX_CREATE_RULE_MSG,
	NSS_IPV4_TX_DESTROY_RULE_MSG,
	NSS_IPV4_RX_ESTABLISH_RULE_MSG,
	NSS_IPV4_RX_CONN_STATS_SYNC_MSG,
	NSS_IPV4_RX_NODE_STATS_SYNC_MSG,
	NSS_IPV4_MAX_MSG_TYPES,
};

/*
 * NA IPv4 rule creation flags.
 */
#define NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
					/* Do not perform sequence number checks */
#define NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
					/* This is a pure bridge forwarding flow */
#define NSS_IPV4_RULE_CREATE_FLAG_ROUTED 0x04
					/* Rule is for a routed connection. */
#define NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING 0x08
					/* Rule is for a DSCP marking . */
#define NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING 0x10
					/* Rule is for a VLAN marking . */

/*
 * IPv4 rule creation validity flags.
 */
#define NSS_IPV4_RULE_CREATE_CONN_VALID 0x01	/* Protocol fields are valid */
#define NSS_IPV4_RULE_CREATE_TCP_VALID 0x02	/* Protocol fields are valid */
#define NSS_IPV4_RULE_CREATE_PPPOE_VALID 0x04	/* PPPoE fields are valid */
#define NSS_IPV4_RULE_CREATE_QOS_VALID 0x08	/* QoS fields are valid */
#define NSS_IPV4_RULE_CREATE_VLAN_VALID 0x10	/* VLAN fields are valid */
#define NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID 0x20	/* DSCP fields are valid */
#define NSS_IPV4_RULE_CREATE_VLAN_MARKING_VALID 0x40	/* VLAN fields are valid */

/*
 * Common 5 tuple structure
 */
struct nss_ipv4_5tuple {
	uint32_t flow_ip;		/* Flow IP address */
	uint32_t flow_ident;		/* Flow ident (e.g. port) */
	uint32_t return_ip;		/* Return IP address */
	uint32_t return_ident;		/* Return ident (e.g. port) */
	uint8_t protocol;		/* Protocol number */
	uint8_t reserved[3];		/* Padded for alignment */
};

/*
 * Connection create structure
 */
struct nss_ipv4_connection_rule {
	uint16_t flow_mac[3];		/* Flow MAC address */
	uint16_t return_mac[3];		/* Return MAC address */
	int32_t flow_interface_num;	/* Flow interface number */
	int32_t return_interface_num;	/* Return interface number */
	uint32_t flow_mtu;		/* Flow interface`s MTU */
	uint32_t return_mtu;		/* Return interface`s MTU */
	uint32_t flow_ip_xlate;		/* Translated flow IP address */
	uint32_t return_ip_xlate;	/* Translated return IP address */
	uint32_t flow_ident_xlate;	/* Translated flow ident (e.g. port) */
	uint32_t return_ident_xlate;	/* Translated return ident (e.g. port) */
};

/*
 * PPPoE connection rules structure
 */
struct nss_ipv4_pppoe_rule {
	uint16_t flow_pppoe_session_id;	/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow direction`s PPPoE Server MAC address */
	uint16_t return_pppoe_session_id;
					/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return direction's PPPoE Server MAC address */
};

/*
 * DSCP connection rule structure
 */
struct nss_ipv4_dscp_rule {
	uint8_t dscp_itag;		/* Input tag for DSCP marking */
	uint8_t dscp_imask;		/* Input mask for DSCP marking */
	uint8_t dscp_omask;		/* Output mask for DSCP marking */
	uint8_t dscp_oval;		/* Output value of DSCP marking */
};

/*
 * Action types for VLAN
 */
enum nss_ipv4_vlan_action_types {
	NSS_IPV4_VLAN_MATCH = 0,
	NSS_IPV4_VLAN_ADD = 1,
	NSS_IPV4_VLAN_REMOVE = 2,
};

/*
 * VLAN connection rule structure
 */
struct nss_ipv4_vlan_rule {
	uint16_t ingress_vlan_tag;	/* VLAN Tag for the ingress packets */
	uint16_t egress_vlan_tag;	/* VLAN Tag for egress packets */
	uint16_t vlan_itag;		/* Input tag for VLAN marking */
	uint16_t vlan_imask;		/* Input mask for VLAN marking */
	uint16_t vlan_omask;		/* Output mask for VLAN marking */
	uint16_t vlan_oval;		/* Output value of VLAN marking */
	uint8_t action;			/* The type of action to perform */
	uint8_t reserved[3];		/* Padded for alignment */
};

/*
 * TCP connection rule structure
 */
struct nss_ipv4_protocol_tcp_rule {
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint8_t flow_window_scale;	/* Flow direction's window scaling factor */
	uint8_t return_window_scale;	/* Return direction's window scaling factor */
	uint16_t reserved;		/* Padded for alignment */
};

/*
 * QoS connection rule structure
 */
struct nss_ipv4_qos_rule {
	uint32_t qos_tag;		/* QoS tag associated with this rule */
};

/*
 * Error types for ipv4 messages
 */
enum nss_ipv4_error_response_types {
	NSS_IPV4_CR_INVALID_PNODE_ERROR = 1,
	NSS_IPV4_CR_MISSING_CONNECTION_RULE_ERROR,
	NSS_IPV4_CR_BUFFER_ALLOC_FAIL_ERROR,
	NSS_IPV4_CR_PPPOE_SESSION_CREATION_ERROR,
	NSS_IPV4_DR_NO_CONNECTION_ENTRY_ERROR,
	NSS_IPV4_UNKNOWN_MSG_TYPE,
	NSS_IPV4_LAST
};

/*
 * The IPv4 rule create sub-message structure.
 */
struct nss_ipv4_rule_create_msg {
	/* Request */
	struct nss_ipv4_5tuple tuple;			/* Holds values of the 5 tuple */

	struct nss_ipv4_connection_rule conn_rule;	/* Basic connection specific data */
	struct nss_ipv4_protocol_tcp_rule tcp_rule;	/* TCP related accleration parameters */
	struct nss_ipv4_pppoe_rule pppoe_rule;		/* PPPoE related accleration parameters */
	struct nss_ipv4_qos_rule qos_rule;		/* QoS related accleration parameters */
	struct nss_ipv4_dscp_rule dscp_rule;		/* DSCP related accleration parameters */
	struct nss_ipv4_vlan_rule vlan_primary_rule;	/* Primary VLAN related accleration parameters */
	struct nss_ipv4_vlan_rule vlan_secondary_rule;	/* Secondary VLAN related accleration parameters */

	uint16_t valid_flags;				/* Bit flags associated with the validity of parameters */
	uint16_t rule_flags;				/* Bit flags associated with the rule */

	/* Response */
	uint32_t index;					/* Slot ID for cache stats to host OS */
};

/*
 * The IPv4 rule destroy sub-message structure.
 */
struct nss_ipv4_rule_destroy_msg {
	struct nss_ipv4_5tuple tuple;	/* Holds values of the 5 tuple */
};

/*
 * The NSS IPv4 rule establish structure.
 */
struct nss_ipv4_rule_establish {
	uint32_t index;				/* Slot ID for cache stats to host OS */
	uint32_t protocol;			/* Protocol number */
	int32_t flow_interface;			/* Flow interface number */
	uint32_t flow_mtu;			/* MTU for flow interface */
	uint32_t flow_ip;			/* Flow IP address */
	uint32_t flow_ip_xlate;			/* Translated flow IP address */
	uint32_t flow_ident;			/* Flow ident (e.g. port) */
	uint32_t flow_ident_xlate;		/* Translated flow ident (e.g. port) */
	uint16_t flow_mac[3];			/* Flow direction source MAC address */
	uint16_t flow_pppoe_session_id;		/* Flow direction`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];	/* Flow direction`s PPPoE Server MAC address */
	uint16_t ingress_vlan_tag;		/* Ingress VLAN tag */
	int32_t return_interface;		/* Return interface number */
	uint32_t return_mtu;			/* MTU for return interface */
	uint32_t return_ip;			/* Return IP address */
	uint32_t return_ip_xlate;		/* Translated return IP address */
	uint32_t return_ident;			/* Return ident (e.g. port) */
	uint32_t return_ident_xlate;		/* Translated return ident (e.g. port) */
	uint16_t return_mac[3];			/* Return direction source MAC address */
	uint16_t return_pppoe_session_id;	/* Return direction's PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];	/* Return direction's PPPoE Server MAC address */
	uint16_t egress_vlan_tag;		/* Egress VLAN tag */
	uint32_t flags;				/* Bit flags associated with the rule */
	uint32_t qos_tag;			/* Qos Tag */
};

/*
 * IPv4 rule sync reasons.
 */
#define NSS_IPV4_RULE_SYNC_REASON_STATS 0
					/* Sync is to synchronize stats */
#define NSS_IPV4_RULE_SYNC_REASON_FLUSH 1
					/* Sync is to flush a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_EVICT 2
					/* Sync is to evict a cache entry */
#define NSS_IPV4_RULE_SYNC_REASON_DESTROY 3
					/* Sync is to destroy a cache entry (requested by host OS) */
#define NSS_IPV4_RULE_SYNC_REASON_PPPOE_DESTROY 4
					/* Sync is to destroy a cache entry which belongs to a particular PPPoE session */

/*
 * The NSS IPv4 rule sync structure.
 */
struct nss_ipv4_conn_sync {
	uint32_t index;			/* Slot ID for cache stats to host OS */
	uint32_t flow_max_window;	/* Flow direction's largest seen window */
	uint32_t flow_end;		/* Flow direction's largest seen sequence + segment length */
	uint32_t flow_max_end;		/* Flow direction's largest seen ack + max(1, win) */
	uint32_t flow_rx_packet_count;	/* Flow interface's RX packet count */
	uint32_t flow_rx_byte_count;	/* Flow interface's RX byte count */
	uint32_t flow_tx_packet_count;	/* Flow interface's TX packet count */
	uint32_t flow_tx_byte_count;	/* Flow interface's TX byte count */
	uint16_t flow_pppoe_session_id; /* Flow interface`s PPPoE session ID. */
	uint16_t flow_pppoe_remote_mac[3];
					/* Flow interface's PPPoE remote server MAC address if there is any */
	uint32_t return_max_window;	/* Return direction's largest seen window */
	uint32_t return_end;		/* Return direction's largest seen sequence + segment length */
	uint32_t return_max_end;	/* Return direction's largest seen ack + max(1, win) */
	uint32_t return_rx_packet_count;
					/* Return interface's RX packet count */
	uint32_t return_rx_byte_count;	/* Return interface's RX byte count */
	uint32_t return_tx_packet_count;
					/* Return interface's TX packet count */
	uint32_t return_tx_byte_count;	/* Return interface's TX byte count */
	uint16_t return_pppoe_session_id;
					/* Return interface`s PPPoE session ID. */
	uint16_t return_pppoe_remote_mac[3];
					/* Return interface's PPPoE remote server MAC address if there is any */
	uint32_t inc_ticks;		/* Number of ticks since the last sync */
	uint32_t reason;		/* Reason for the sync */

	uint8_t flags;			/* Bit flags associated with the rule */
	uint32_t qos_tag;		/* Qos Tag */
};

/*
 * Exception events from bridge/route handler
 */
enum exception_events_ipv4 {
	NSS_EXCEPTION_EVENT_IPV4_ICMP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_UNHANDLED_TYPE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_FLUSH_TO_HOST,
	NSS_EXCEPTION_EVENT_IPV4_TCP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_TCP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_TCP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_TCP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_TCP_FLAGS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SEQ_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SMALL_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_BAD_SACK,
	NSS_EXCEPTION_EVENT_IPV4_TCP_BIG_DATA_OFFS,
	NSS_EXCEPTION_EVENT_IPV4_TCP_SEQ_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_ACK_EXCEEDS_RIGHT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_TCP_ACK_BEFORE_LEFT_EDGE,
	NSS_EXCEPTION_EVENT_IPV4_UDP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UDP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_UDP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_UDP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_UDP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_UDP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_WRONG_TARGET_MAC,
	NSS_EXCEPTION_EVENT_IPV4_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_BAD_TOTAL_LENGTH,
	NSS_EXCEPTION_EVENT_IPV4_BAD_CHECKSUM,
	NSS_EXCEPTION_EVENT_IPV4_NON_INITIAL_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_DATAGRAM_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_OPTIONS_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UNKNOWN_PROTOCOL,
	NSS_EXCEPTION_EVENT_IPV4_ESP_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_ESP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_ESP_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_ESP_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_ESP_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_ESP_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_IVID_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_DSCP_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_VLAN_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_MAX
};

/*
 * IPv4 node statistics structure
 */
struct nss_ipv4_node_sync {
	struct nss_cmn_node_stats node_stats;
				/* Common node stats for IPv4 */
	uint32_t ipv4_connection_create_requests;
				/* Number of IPv4 connection create requests */
	uint32_t ipv4_connection_create_collisions;
				/* Number of IPv4 connection create requests that collided with existing entries */
	uint32_t ipv4_connection_create_invalid_interface;
				/* Number of IPv4 connection create requests that had invalid interface */
	uint32_t ipv4_connection_destroy_requests;
				/* Number of IPv4 connection destroy requests */
	uint32_t ipv4_connection_destroy_misses;
				/* Number of IPv4 connection destroy requests that missed the cache */
	uint32_t ipv4_connection_hash_hits;
				/* Number of IPv4 connection hash hits */
	uint32_t ipv4_connection_hash_reorders;
				/* Number of IPv4 connection hash reorders */
	uint32_t ipv4_connection_flushes;
				/* Number of IPv4 connection flushes */
	uint32_t ipv4_connection_evictions;
				/* Number of IPv4 connection evictions */
	uint32_t exception_events[NSS_EXCEPTION_EVENT_IPV4_MAX];
				/* Number of IPv4 exception events */
};

/*
 * Message structure to send/receive IPv4 bridge/route commands
 */
struct nss_ipv4_msg {
	struct nss_cmn_msg cm;		/* Message Header */
	union {
		struct nss_ipv4_rule_create_msg rule_create;	/* Message: rule create */
		struct nss_ipv4_rule_destroy_msg rule_destroy;	/* Message: rule destroy */
		struct nss_ipv4_rule_establish rule_establish;	/* Message: rule establish confirmation */
		struct nss_ipv4_conn_sync conn_stats;	/* Message: connection stats sync */
		struct nss_ipv4_node_sync node_stats;	/* Message: node stats sync */
	} msg;
};

typedef void (*nss_ipv4_msg_callback_t)(void *app_data, struct nss_ipv4_msg *msg);
extern nss_tx_status_t nss_ipv4_tx(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_msg *msg);
extern struct nss_ctx_instance *nss_ipv4_notify_register(nss_ipv4_msg_callback_t cb, void *app_data);
extern void nss_ipv4_notify_unregister(void);
extern struct nss_ctx_instance *nss_ipv4_get_mgr(void);
extern void nss_ipv4_register_handler(void);

#endif /* __NSS_IPV4_H */

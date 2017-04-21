/*
 **************************************************************************
 * Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
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
 * @file nss_ipv4.h
 *	NSS IPv4 interface definitions.
 */

#ifndef __NSS_IPV4_H
#define __NSS_IPV4_H

/**
 * @addtogroup nss_ipv4_subsystem
 * @{
 */

/**
 * nss_ipv4_message_types
 *	IPv4 bridge and routing rule message types.
 */
enum nss_ipv4_message_types {
	NSS_IPV4_TX_CREATE_RULE_MSG,
	NSS_IPV4_TX_DESTROY_RULE_MSG,
	NSS_IPV4_RX_DEPRECATED0,		/**< Deprecated: NSS_IPV4_RX_ESTABLISH_RULE_MSG. ??what does this mean - customer is to use this msg? Can't find it in the headers */
	NSS_IPV4_RX_CONN_STATS_SYNC_MSG,
	NSS_IPV4_RX_NODE_STATS_SYNC_MSG,
	NSS_IPV4_TX_CONN_CFG_RULE_MSG,
	NSS_IPV4_TX_CREATE_MC_RULE_MSG,
	NSS_IPV4_TX_CONN_STATS_SYNC_MANY_MSG,
	NSS_IPV4_TX_ACCEL_MODE_CFG_MSG,
	NSS_IPV4_MAX_MSG_TYPES,
};

/*
 * NA IPv4 rule creation & rule update flags.
 */
#define NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK 0x01
		/**< Do not perform TCP sequence number checks. */
#define NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW 0x02
		/**< Pure bridge forwarding flow. */
#define NSS_IPV4_RULE_CREATE_FLAG_ROUTED 0x04
		/**< Rule for a routed connection. */
#define NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING 0x08
		/**< Rule for configuring DSCP marking. */
#define NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING 0x10
		/**< Rule for configuring VLAN marking. */
#define NSS_IPV4_RULE_UPDATE_FLAG_CHANGE_MTU 0x20
		/**< Update MTU of the connection interfaces. */
#define NSS_IPV4_RULE_CREATE_FLAG_ICMP_NO_CME_FLUSH 0x40
		/**< Rule for not flushing CME on an ICMP packet. */

/**
 * L2 payload is not IPv4, but it consists of an encapsulating protocol that
 * carries an IPv4 payload within it.
 */
#define NSS_IPV4_RULE_CREATE_FLAG_L2_ENCAP 0x80

/*
 * Validity flags for rule creation.
 */
#define NSS_IPV4_RULE_CREATE_CONN_VALID 0x01	/**< Connection is valid. */
#define NSS_IPV4_RULE_CREATE_TCP_VALID 0x02	/**< TCP protocol fields are valid. */
#define NSS_IPV4_RULE_CREATE_PPPOE_VALID 0x04	/**< PPPoE fields are valid. */
#define NSS_IPV4_RULE_CREATE_QOS_VALID 0x08	/**< QoS fields are valid. */
#define NSS_IPV4_RULE_CREATE_VLAN_VALID 0x10	/**< VLAN fields are valid. */
#define NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID 0x20
		/**< DSCP marking fields are valid. */
#define NSS_IPV4_RULE_CREATE_VLAN_MARKING_VALID 0x40
		/**< VLAN marking fields are valid. */
#define NSS_IPV4_RULE_CREATE_SRC_MAC_VALID 0x80
		/**< Source MAC address fields are valid. */
#define NSS_IPV4_RULE_CREATE_NEXTHOP_VALID 0x100
		/**< Next hop interface number fields are valid. */

/*
 * Multicast command rule flags
 */
#define NSS_IPV4_MC_RULE_CREATE_FLAG_MC_UPDATE 0x01	/**< Multicast rule update. */

/*
 * Multicast command validity flags
 */
#define NSS_IPV4_MC_RULE_CREATE_FLAG_QOS_VALID 0x01
		/**< QoS fields are valid. */
#define NSS_IPV4_MC_RULE_CREATE_FLAG_DSCP_MARKING_VALID 0x02
		/**< DSCP fields are valid. */
#define NSS_IPV4_MC_RULE_CREATE_FLAG_INGRESS_VLAN_VALID 0x04
		/**< Ingress VLAN fields are valid. */
#define NSS_IPV4_MC_RULE_CREATE_FLAG_INGRESS_PPPOE 0x08
		/**< Ingress PPPoE fields are valid. */

/*
 * Multicast connection per-interface rule flags (to be used with rule_flags field of nss_ipv4_mc_if_rule structure)
 */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_BRIDGE_FLOW 0x01
		/**< Bridge flow. ??need more info */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_ROUTED_FLOW 0x02
		/**< Routed flow. ??need more info */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_JOIN 0x04
		/**< Interface has joined the flow. */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_LEAVE 0x08
		/**< Interface has left the flow. */

/*
 * Multicast connection per-interface valid flags (to be used with valid_flags field of nss_ipv4_mc_if_rule structure)
 */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_VLAN_VALID 0x01
		/**< VLAN fields are valid. */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_PPPOE_VALID 0x02
		/**< PPPoE fields are valid. */
#define NSS_IPV4_MC_RULE_CREATE_IF_FLAG_NAT_VALID 0x4
		/**< Interface is configured with the source NAT. */

/*
 * Source MAC address valid flags (to be used with mac_valid_flags field of nss_ipv4_src_mac_rule structure)
 */
#define NSS_IPV4_SRC_MAC_FLOW_VALID 0x01
		/**< MAC address for the flow interface is valid. */
#define NSS_IPV4_SRC_MAC_RETURN_VALID 0x02
		/**< MAC address for the return interface is valid. */

/**
 * nss_ipv4_5tuple
 *	Common 5-tuple information.
 */
struct nss_ipv4_5tuple {
	uint32_t flow_ip;		/**< Flow IP address. */
	uint32_t flow_ident;		/**< Flow identifier (e.g., TCP or UDP port). */
	uint32_t return_ip;		/**< Return IP address. */
	uint32_t return_ident;		/**< Return identier (e.g., TCP or UDP port). */
	uint8_t protocol;		/**< Protocol number. */
	uint8_t reserved[3];		/**< Padded for alignment. */
};

/**
 * nss_ipv4_connection_rule
 *	Information for creating a connection.
 */
struct nss_ipv4_connection_rule {
	uint16_t flow_mac[3];		/**< Flow MAC address. */
	uint16_t return_mac[3];		/**< Return MAC address. */
	int32_t flow_interface_num;	/**< Flow interface number. */
	int32_t return_interface_num;	/**< Return interface number. */
	uint32_t flow_mtu;		/**< MTU for the flow interface. */
	uint32_t return_mtu;		/**< MTU for the return interface. */
	uint32_t flow_ip_xlate;		/**< Translated flow IP address. */
	uint32_t return_ip_xlate;	/**< Translated return IP address. */
	uint32_t flow_ident_xlate;	/**< Translated flow identifier (e.g., port). */
	uint32_t return_ident_xlate;	/**< Translated return identifier (e.g., port). */
};

/**
 * nss_ipv4_pppoe_rule
 *	v4_protocol_tcp_rule
 *	Information for PPPoE connection rules.
 */
struct nss_ipv4_pppoe_rule {
	uint16_t flow_pppoe_session_id;
			/**< PPPoE session ID for the flow direction. */
	uint16_t flow_pppoe_remote_mac[3];
			/**< PPPoE Server MAC address for the flow direction. */
	uint16_t return_pppoe_session_id;
			/**< PPPoE session ID for the return direction. */
	uint16_t return_pppoe_remote_mac[3];
			/**< PPPoE Server MAC address for the return direction. */
};

/**
 * nss_ipv4_dscp_rule
 *	Information for DSCP connection rules.
 */
struct nss_ipv4_dscp_rule {
	uint8_t flow_dscp;	/**< Egress DSCP value for the flow direction. */
	uint8_t return_dscp;	/**< Egress DSCP value for the return direction. */
	uint8_t reserved[2];	/**< Padded for alignment. */
};

/**
 * nss_ipv4_vlan_rule
 *	Information for VLAN connection rules.
 */
struct nss_ipv4_vlan_rule {
	uint32_t ingress_vlan_tag;	/**< VLAN tag for the ingress packets. */
	uint32_t egress_vlan_tag;	/**< VLAN tag for egress packets. */
};

/**
 * nss_ipv4_nexthop
 *	Information for next hop interface numbers. ??new
 *
 * A next hop is the next interface that will receive the packet (as opposed to
 * the final interface that the packet will go out on ??out on what?).
 */
struct nss_ipv4_nexthop {
	int32_t flow_nexthop;		/**< Flow next hop interface number. ??doesn't make sense */
	int32_t return_nexthop;		/**< Return next hop interface number. ??does this mean the next number is being returned? */
};

/**
 * nss_ipv4_protocol_tcp_rule
 *	Information for TCP connection rules.
 */
struct nss_ipv4_protocol_tcp_rule {
	uint32_t flow_max_window;
			/**< Largest seen window for the flow direction. */
	uint32_t return_max_window;
			/**< Largest seen window for the return direction. */

	/**
	 * Largest seen sequence + segment length for the flow direction.
	 */
	uint32_t flow_end;

	/**
	 * Largest seen sequence + segment length for the return direction.
	 */
	uint32_t return_end;

	uint32_t flow_max_end;
			/**< Largest seen ack + max(1, win) for the flow direction. */
	uint32_t return_max_end;
			/**< Largest seen ack + max(1, win) for the return direction. */
	uint8_t flow_window_scale;
			/**< Window scaling factor for the flow direction. */
	uint8_t return_window_scale;
			/**< Window scaling factor for the return direction. */
	uint16_t reserved;		/**< Alignment padding. */
};

/**
 * nss_ipv4_qos_rule
 *	Information for QoS connection rules.
 */
struct nss_ipv4_qos_rule {
	uint32_t flow_qos_tag;
			/**< QoS tag associated with this rule for the flow direction. */
	uint32_t return_qos_tag;
			/**< QoS tag associated with this rule for the return direction. */
};

/**
 * nss_ipv4_src_mac_rule
 *	Information for source MAC address rules.
 */
struct nss_ipv4_src_mac_rule {
	uint32_t mac_valid_flags;	/**< MAC address validity flags. */
	uint16_t flow_src_mac[3];	/**< Source MAC address for the flow direction. */
	uint16_t return_src_mac[3];	/**< Source MAC address for the return direction. */
};

/**
 * nss_ipv4_error_response_types
 *	Error types for IPv4 messages.
 */
enum nss_ipv4_error_response_types {
	NSS_IPV4_UNKNOWN_MSG_TYPE = 1,
	NSS_IPV4_CR_INVALID_PNODE_ERROR,
	NSS_IPV4_CR_MISSING_CONNECTION_RULE_ERROR,
	NSS_IPV4_CR_BUFFER_ALLOC_FAIL_ERROR,
	NSS_IPV4_CR_PPPOE_SESSION_CREATION_ERROR,
	NSS_IPV4_DR_NO_CONNECTION_ENTRY_ERROR,
	NSS_IPV4_CR_CONN_CFG_ALREADY_CONFIGURED_ERROR,
	NSS_IPV4_CR_CONN_CFG_NOT_MULTIPLE_OF_QUANTA_ERROR,
	NSS_IPV4_CR_CONN_CFG_EXCEEDS_LIMIT_ERROR,
	NSS_IPV4_CR_CONN_CFG_MEM_ALLOC_FAIL_ERROR,
	NSS_IPV4_CR_MULTICAST_INVALID_PROTOCOL,
	NSS_IPV4_CR_MULTICAST_UPDATE_INVALID_FLAGS,
	NSS_IPV4_CR_MULTICAST_UPDATE_INVALID_IF,
	NSS_IPV4_CR_ACCEL_MODE_CONFIG_INVALID,
	NSS_IPV4_LAST
};

/**
 * nss_ipv4_rule_create_msg
 *	IPv4 rule for creating sub-messages.
 */
struct nss_ipv4_rule_create_msg {
	/*
	 * Request
	 */
	uint16_t valid_flags;
			/**< Bit flags associated with the validity of parameters. */
	uint16_t rule_flags;
			/**< Bit flags associated with the rule. */
	struct nss_ipv4_5tuple tuple;
			/**< Holds values of the 5 tuple. */
	struct nss_ipv4_connection_rule conn_rule;
			/**< Basic connection-specific data. */
	struct nss_ipv4_protocol_tcp_rule tcp_rule;
			/**< TCP-related accleration parameters. */
	struct nss_ipv4_pppoe_rule pppoe_rule;
			/**< PPPoE-related accleration parameters. */
	struct nss_ipv4_qos_rule qos_rule;
			/**< QoS-related accleration parameters. */
	struct nss_ipv4_dscp_rule dscp_rule;
			/**< DSCP-related accleration parameters. */
	struct nss_ipv4_vlan_rule vlan_primary_rule;
			/**< Primary VLAN-related accleration parameters. */
	struct nss_ipv4_vlan_rule vlan_secondary_rule;
			/**< Secondary VLAN-related accleration parameters. */
	struct nss_ipv4_src_mac_rule src_mac_rule;
			/**< Source MAC address-related acceleration parameters. */
	struct nss_ipv4_nexthop nexthop_rule;
			/**< Parameters related to the next hop. */

	/*
	 * Response
	 */
	uint32_t reserved;		/**< Alignment padding. ??is this comment correct? */
};

/**
 * nss_ipv4_mc_if_rule
 *	IPv4 multicast rule for creating per-interface information.
 */
struct nss_ipv4_mc_if_rule {
	uint16_t rule_flags;		/**< Bit flags associated with the rule. */
	uint16_t valid_flags;
			/**< Bit flags associated with the validity of parameters. */
	uint32_t xlate_src_ip;		/**< Translated flow IP address. */
	uint32_t xlate_src_ident;	/**< Translated flow identifier (e.g., port). */
	uint32_t egress_vlan_tag[MAX_VLAN_DEPTH];
					/**< VLAN tag stack for the egress packets. */
	uint16_t pppoe_session_id;	/**< PPPoE session ID. */
	uint16_t pppoe_remote_mac[3];	/**< PPPoE server MAC address. */
	uint32_t if_num;		/**< Interface number. */
	uint32_t if_mtu;		/**< Interface MTU. */
	uint16_t if_mac[3];		/**< Interface MAC address. */
	uint8_t reserved[2];		/**< Reserved for ?? bytes. */
};

/**
 * nss_ipv4_mc_rule_create_msg
 *	IPv4 multicast rule for creating sub-messages.
 */
struct nss_ipv4_mc_rule_create_msg {
	struct nss_ipv4_5tuple tuple;		/**< Holds values of the 5 tuple. */

	uint32_t rule_flags;			/**< Multicast command rule flags. */
	uint32_t valid_flags;			/**< Multicast command validity flags. */
	uint32_t src_interface_num;
			/**< Source interface number (virtual or physical). */
	uint32_t ingress_vlan_tag[MAX_VLAN_DEPTH];
			/**< VLAN tag stack for the ingress packets. */
	uint16_t ingress_pppoe_session_id;	/**< PPPoE session ID at ingress. */
	uint16_t ingress_pppoe_remote_mac[3];	/**< PPPoE server MAC address. */
	uint32_t qos_tag;			/**< QoS tag for the rule. */
	uint16_t dest_mac[3];			/**< Destination multicast MAC address. */
	uint16_t if_count;			/**< Number of destination interfaces. */
	uint8_t egress_dscp;			/**< Egress DSCP value for the flow. */
	uint8_t reserved[3];			/**< Reserved for ?? bytes. */

	struct nss_ipv4_mc_if_rule if_rule[NSS_MC_IF_MAX];
						/**< Per-interface information. */
};

/**
 * nss_ipv4_rule_destroy_msg
 *	IPv4 rule for destroying sub-messages.
 */
struct nss_ipv4_rule_destroy_msg {
	struct nss_ipv4_5tuple tuple;	/**< Holds values of the 5 tuple. */
};

/**
 * nss_ipv4_rule_conn_cfg_msg
  *	IPv4 rule for connection configuration sub-messages.
*/
struct nss_ipv4_rule_conn_cfg_msg {
	uint32_t num_conn;		/**< Number of supported IPv4 connections. */
};

/*
 * IPv4 rule synchronization reasons.
 */
#define NSS_IPV4_RULE_SYNC_REASON_STATS 0
		/**< Rule for synchronizing statistics. */
#define NSS_IPV4_RULE_SYNC_REASON_FLUSH 1
		/**< Rule for flushing a cache entry. */
#define NSS_IPV4_RULE_SYNC_REASON_EVICT 2
		/**< Rule for evicting a cache entry. */
#define NSS_IPV4_RULE_SYNC_REASON_DESTROY 3
		/**< Rule for destroying a cache entry (requested by the host OS). */
#define NSS_IPV4_RULE_SYNC_REASON_PPPOE_DESTROY 4
		/**< Rule for destroying a cache entry that belongs to a specific PPPoE session.
 */

/**
 * nss_ipv4_conn_sync
 *	IPv4 synchronized connections. ??is this comment correct?
 */
struct nss_ipv4_conn_sync {
	uint32_t reserved;		/**< Alignment padding. ??is this comment correct?  */
	uint8_t protocol;		/**< Protocol number. */
	uint32_t flow_ip;		/**< Flow IP address. */
	uint32_t flow_ip_xlate;		/**< Translated flow IP address. */
	uint32_t flow_ident;		/**< Flow identifier (e.g., port). */
	uint32_t flow_ident_xlate;	/**< Translated flow identifier (e.g., port). */
	uint32_t flow_max_window;	/**< Largest seen window for the flow direction. */

	/**
	 * Largest seen sequence + segment length for the flow direction.
	 */
	uint32_t flow_end;

	uint32_t flow_max_end;
			/**< Largest seen ack + max(1, win) for the flow direction. */
	uint32_t flow_rx_packet_count;
			/**< Rx packet count for the flow interface. */
	uint32_t flow_rx_byte_count;
			/**< Rx byte count for the flow interface. */
	uint32_t flow_tx_packet_count;
			/**< Tx packet count for the flow interface. */
	uint32_t flow_tx_byte_count;
			/**< Tx byte count for the flow interface. */
	uint16_t flow_pppoe_session_id;
			/**< PPPoE session ID for the flow interface. */

	/**
	 * PPPoE remote server MAC address, if there is any, for the flow interface.
	 */
	uint16_t flow_pppoe_remote_mac[3];

	uint32_t return_ip;		/**< Return IP address. */
	uint32_t return_ip_xlate;	/**< Translated return IP address. */
	uint32_t return_ident;		/**< Return identier (e.g., port). */
	uint32_t return_ident_xlate;	/**< Translated return identifier (e.g., port). */
	uint32_t return_max_window;
			/**< Largest seen window for the return direction. */

	/**
	 * Largest seen sequence + segment length for the return direction.
	 */
	uint32_t return_end;

	uint32_t return_max_end;
			/**< Largest seen ack + max(1, win) for the return direction. */
	uint32_t return_rx_packet_count;
			/**< Rx packet count for the return interface. */
	uint32_t return_rx_byte_count;
			/**< Rx byte count for the return interface. */
	uint32_t return_tx_packet_count;
			/**< Tx packet count for the return interface. */
	uint32_t return_tx_byte_count;
			/**< Tx byte count for the return interface. */
	uint16_t return_pppoe_session_id;
			/**< PPPoE session ID for the return interface. */

	/**
	 * PPPoE remote server MAC address (if any) for the return interface.
	 */
	uint16_t return_pppoe_remote_mac[3];

	uint32_t inc_ticks;	/**< Number of ticks since the last synchronization. */
	uint32_t reason;	/**< Reason for the synchronization. */

	uint8_t flags;		/**< Bit flags associated with the rule. */
	uint32_t qos_tag;	/**< QoS tag. */
	uint32_t cause;		/**< Flush cause associated with the rule. */
};

/**
 * nss_ipv4_conn_sync_many_msg
 *	Message information for synchronized IPv4 connection statistics for many messages. ??is this comment correct?
 */
struct nss_ipv4_conn_sync_many_msg {
	/*
	 * Request
	 */
	uint16_t index;		/**< Request connection statistics from the index. */
	uint16_t size;		/**< Buffer size of this message. */

	/*
	 * Response
	 */
	uint16_t next;	/**< Firmware response for the next connection to be requested. */
	uint16_t count;	/**< Number of synchronized connections included in this message. */
	struct nss_ipv4_conn_sync conn_sync[];	/**< Array for the statistics. */
};

/**
 * nss_ipv4_accel_mode_cfg_msg
 *	IPv4 acceleration mode configuration.
 */
struct nss_ipv4_accel_mode_cfg_msg {
	uint32_t mode;		/**< Type of acceleration mode. */
};

/**
 * exception_events_ipv4
 *	Exception events from the bridge or route handler.
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
	NSS_EXCEPTION_EVENT_IPV4_IVID_MISSING,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_6RD_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_6RD_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_DSCP_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_VLAN_MARKING_MISMATCH,
	NSS_EXCEPTION_EVENT_IPV4_DEPRECATED,
	NSS_EXCEPTION_EVENT_GRE_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_GRE_NO_ICME,
	NSS_EXCEPTION_EVENT_GRE_IP_OPTION,
	NSS_EXCEPTION_EVENT_GRE_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_GRE_SMALL_TTL,
	NSS_EXCEPTION_EVENT_GRE_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_SESSION_MATCH_FAIL,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_INVALID_PROTO,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_NO_CME,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_PPTP_GRE_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_DESTROY,
	NSS_EXCEPTION_EVENT_IPV4_FRAG_DF_SET,
	NSS_EXCEPTION_EVENT_IPV4_FRAG_FAIL,
	NSS_EXCEPTION_EVENT_IPV4_ICMP_IPV4_UDPLITE_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_HEADER_INCOMPLETE,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_IP_OPTION,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_IP_FRAGMENT,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_SMALL_TTL,
	NSS_EXCEPTION_EVENT_IPV4_UDPLITE_NEEDS_FRAGMENTATION,
	NSS_EXCEPTION_EVENT_IPV4_MC_UDP_NO_ICME,
	NSS_EXCEPTION_EVENT_IPV4_MC_MEM_ALLOC_FAILURE,
	NSS_EXCEPTION_EVENT_IPV4_MC_UPDATE_FAILURE,
	NSS_EXCEPTION_EVENT_IPV4_MC_PBUF_ALLOC_FAILURE,
	NSS_EXCEPTION_EVENT_IPV4_MAX
};

/**
 * nss_ipv4_node_sync
 *	IPv4 node synchronization statistics.
 */
struct nss_ipv4_node_sync {
	struct nss_cmn_node_stats node_stats; 	/**< Common node statistics. */
	uint32_t ipv4_connection_create_requests;
			/**< Number of connection create requests. */

	/**
	 * Number of connection create requests that collided with existing entries.
	 */
	uint32_t ipv4_connection_create_collisions;

	/**
	 * Number of connection create requests that had invalid interfaces.
	 */
	uint32_t ipv4_connection_create_invalid_interface;

	uint32_t ipv4_connection_destroy_requests;
			/**< Number of connection destroy requests. */
	uint32_t ipv4_connection_destroy_misses;
			/**< Number of connection destroy requests that missed the cache. */
	uint32_t ipv4_connection_hash_hits;	/**< Number of connection hash hits. */
	uint32_t ipv4_connection_hash_reorders;	/**< Number of connection hash reorders. */
	uint32_t ipv4_connection_flushes;	/**< Number of connection flushes. */
	uint32_t ipv4_connection_evictions;	/**< Number of connection evictions. */
	uint32_t ipv4_fragmentations;
			/**< Number of successful IPv4 fragmentations performed. */
	uint32_t ipv4_mc_connection_create_requests;
			/**< Number of multicast connection create requests. */
	uint32_t ipv4_mc_connection_update_requests;
			/**< Number of multicast connection update requests. */

	/**
	 * Number of multicast connection create requests that had invalid interfaces.
	 */
	uint32_t ipv4_mc_connection_create_invalid_interface;

	uint32_t ipv4_mc_connection_destroy_requests;
			/**< Number of multicast connection destroy requests. */

	/**
	 * Number of multicast connection destroy requests that missed the cache.
	 */
	uint32_t ipv4_mc_connection_destroy_misses;

	uint32_t ipv4_mc_connection_flushes;
			/**< Number of multicast connection flushes. */
	uint32_t exception_events[NSS_EXCEPTION_EVENT_IPV4_MAX];
			/**< Number of exception events. */
};

/**
 * nss_ipv4_msg
 *	Data for sending and receiving IPv4 bridge or routing messages.
 */
struct nss_ipv4_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of an IPv4 bridge or routing message.
	 */
	union {
		struct nss_ipv4_rule_create_msg rule_create;
				/**< Create a rule. */
		struct nss_ipv4_rule_destroy_msg rule_destroy;
				/**< Destroy a rule. */
		struct nss_ipv4_conn_sync conn_stats;
				/**< Synchronize connection statistics. */
		struct nss_ipv4_node_sync node_stats;
				/**< Synchronize node statistics. */
		struct nss_ipv4_rule_conn_cfg_msg rule_conn_cfg;
				/**< Configure a rule connection. */
		struct nss_ipv4_mc_rule_create_msg mc_rule_create;
				/**< Create a multicast rule. */
		struct nss_ipv4_conn_sync_many_msg conn_stats_many;
				/**< Synchronize connection statistics. */
		struct nss_ipv4_accel_mode_cfg_msg accel_mode_cfg;
				/**< Acceleration ??accelerated? mode. */
	} msg;			/**< Message payload. ??is this comment correct? I assumed it's the message payload because the first field is the message header */
};

extern int nss_ipv6_conn_cfg;	/**< ??description here. */

#ifdef __KERNEL__ /* only kernel will use. */

/**
 * nss_ipv4_max_conn_count
 *	Returns the maximum number of IPv4 connections that the NSS acceleration
 *	engine supports.
 *
 * @return
 * Number of connections that can be accelerated.
 */
int nss_ipv4_max_conn_count(void);

/**
 * Callback function for receiving IPv4 messages.
 *
 * @datatypes
 * nss_ipv4_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_ipv4_msg_callback_t)(void *app_data, struct nss_ipv4_msg *msg);

/**
 * nss_ipv4_tx
 *	Transmits an IPv4 message to the NSS.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_ipv4_msg
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 * @param[in]     msg      Pointer to the message data.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_ipv4_tx(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_msg *msg);

/**
 * nss_ipv4_tx_with_size
 *	Transmits an IPv4 message with a specified size to the NSS.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_ipv4_msg
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 * @param[in]     msg      Pointer to the message data.
 * @param[in]     size     Actual size of this message.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_ipv4_tx_with_size(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_msg *msg, uint32_t size);

/**
 * nss_ipv4_notify_register
 *	Registers a notifier callback with the NSS for ??sending and receiving? IPv4 messages.
 *
 * @datatypes
 * nss_ipv4_msg_callback_t
 *
 * @param[in] cb        Callback function for the message.
 * @param[in] app_data  Pointer to the application context of the message.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_ipv4_notify_register(nss_ipv4_msg_callback_t cb, void *app_data);

/**
 * nss_ipv4_notify_unregister
 *	Degisters an IPv4 message notifier callback from the NSS.
 *
 * @return
 * None.
 *
 * @dependencies
 * The notifier callback must have been previously registered.
 */
extern void nss_ipv4_notify_unregister(void);

/**
 * nss_ipv4_conn_sync_many_notify_register
 *	Registers a notifier callback with the NSS for connection synchronization
 *	message responses.
 *
 * @datatypes
 * nss_ipv4_msg_callback_t
 *
 * @param[in] cb  Callback function for the message.
 *
 * @return
 * None.
 */
extern void nss_ipv4_conn_sync_many_notify_register(nss_ipv4_msg_callback_t cb);

/**
 * nss_ipv4_conn_sync_many_notify_unregister
 *	Degisters a connection synchronization notifier callback from the NSS.
 *
 * @return
 * None.
 *
 * @dependencies
 * The notifier callback must have been previously registered.
 */
extern void nss_ipv4_conn_sync_many_notify_unregister(void);

/**
 * nss_ipv4_get_mgr
 *	Gets the NSS context that is managing IPv4 ??IPv4 what?.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_ipv4_get_mgr(void);

/**
 * nss_ipv4_register_handler
 *	Registers the IPv4 message handler.
 *
 * @return
 * None.
 */
extern void nss_ipv4_register_handler(void);

/**
 * nss_ipv4_register_sysctl
 *	Registers the IPv4 system control ??.
 *
 * @return
 * None.
 */
extern void nss_ipv4_register_sysctl(void);

/**
 * nss_ipv4_unregister_sysctl
 *	Deregisters the IPv4 system control ??.
 *
 * @return
 * None.
 *
 * @dependencies
 * The ?? must have been previously registered.
 */
extern void nss_ipv4_unregister_sysctl(void);

/**
 * nss_ipv4_msg_init
 *	Initializes IPv4 messages.
 *
 * @datatypes
 * nss_ipv4_msg \n
 * nss_ipv4_msg_callback_t
 *
 * @param[in,out] nim       Pointer to the NSS interface message.
 * @param[in]     if_num    NSS interface number.
 * @param[in]     type      Type of message.
 * @param[in]     len       Size of the payload.
 * @param[in]     cb        Callback function for the message.
 * @param[in]     app_data  Pointer to the application context of the message.
 *
 * @return
 * None.
 */
extern void nss_ipv4_msg_init(struct nss_ipv4_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
			nss_ipv4_msg_callback_t cb, void *app_data);

/**
 * nss_ipv4_update_conn_count
 *	Sets the maximum number of IPv4 connections.
 *
 * @param[in] ipv4_max_conn  Maximum number.
 *
 * @return
 * 0 -- Success
 */
extern int nss_ipv4_update_conn_count(int ipv4_max_conn);

/*
 * Logger APIs
 */

/**
 * nss_ipv4_log_tx_msg
 *	Sends an IPV4 logger message. ??correct?
 *
 * @datatypes
 * nss_ipv4_msg
 *
 * @param[in] nim  Pointer to the NSS interface message.
 *
 * @return
 * None.
 */
void nss_ipv4_log_tx_msg(struct nss_ipv4_msg *nim);

/**
 * nss_ipv4_log_rx_msg
 *	Receives an IPV4 logger message. ??correct?
 *
 * @datatypes
 * nss_ipv4_msg
 *
 * @param[in] nim  Pointer to the NSS interface message.
 *
 * @return
 * None.
 */
void nss_ipv4_log_rx_msg(struct nss_ipv4_msg *nim);

#endif /*__KERNEL__ */

/**
 * @}
 */

#endif /* __NSS_IPV4_H */

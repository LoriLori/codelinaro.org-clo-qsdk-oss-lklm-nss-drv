/*
 **************************************************************************
 * Copyright (c) 2014-2015, 2017 The Linux Foundation. All rights reserved.
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

/**
 * nss_gre_redir.h
 *	NSS GRE Redirect interface definitions.
 */

#ifndef __NSS_GRE_REDIR_H
#define __NSS_GRE_REDIR_H

/**
 * @addtogroup nss_gre_redirect_subsystem
 * @{
 */

#define NSS_GRE_REDIR_MAX_INTERFACES 24
		/**< Maximum number of redirect interfaces. */
#define NSS_GRE_REDIR_IP_DF_OVERRIDE_FLAG 0x80		/**< ??Description here. */
#define NSS_GRE_REDIR_PER_PACKET_METADATA_OFFSET 4	/**< ??Description here. */
#define NSS_GRE_REDIR_IP_HDR_TYPE_IPV4 1		/**< Redirect type is IPV4. */
#define NSS_GRE_REDIR_IP_HDR_TYPE_IPV6 2		/**< Redirect type is IPV6. */

/**
 * nss_gre_redir_direction
 *	Direction of a packet.
 *
 * When a packet goes from the host to the NSS, the host sets
 * nss_gre_redir_encap_per_pkt_metadata::dir to #NSS_GRE_REDIR_HLOS_TO_NSS.
 * In this case, the packet is an exception packet. Handle it appropriately.
 *
 * When a packet goes from the NSS to the host, the NSS sets
 * nss_gre_redir_decap_per_pkt_metadata::dir to #NSS_GRE_REDIR_NSS_TO_HLOS.
 */
enum nss_gre_redir_direction {
	NSS_GRE_REDIR_HLOS_TO_NSS = 1,
	NSS_GRE_REDIR_NSS_TO_HLOS = 2
};

/**
 * nss_gre_redir_message_types
 *	Message types for GRE redirect requests and responses.
 */
enum nss_gre_redir_message_types {
	NSS_GRE_REDIR_TX_TUNNEL_CONFIGURE_MSG,
	NSS_GRE_REDIR_TX_INTERFACE_MAP_MSG,
	NSS_GRE_REDIR_TX_INTERFACE_UNMAP_MSG,
	NSS_GRE_REDIR_RX_STATS_SYNC_MSG,
	NSS_GRE_REDIR_MAX_MSG_TYPES,
};

/**
 * nss_gre_redir_configure_msg
 *	Message information for configuring GRE redirection.
 */
struct nss_gre_redir_configure_msg {
	uint32_t ip_hdr_type;		/**< IP header type (IPv4 or IPv6). */

	/**
	 * IPv4 or IPv6 source address (lower 4 bytes are applicable for IPv4).
	 */
	uint32_t ip_src_addr[4];

	/**
	 * IPv4 or IPv6 destination address (lower 4 bytes are applicable for IPv4).
	 */
	uint32_t ip_dest_addr[4];

	uint8_t ip_df_policy;	/**< Default Do Not Fragment policy for the IP header. */
	uint8_t ip_ttl;		/**< Time-to-live value for the IP header. */
	uint8_t gre_version;	/**< Header version. */

	/**
	 * ??description here
	 * - 0 -- Use core 0
	 * - 1 -- Use core 1 @tablebulletend
	 */
	uint8_t rps_hint;
};

/**
 * nss_gre_redir_interface_map_msg
 *	Message information for GRE redirect mapping.
 */
struct nss_gre_redir_interface_map_msg {
	uint32_t nss_if_num;
			/**< NSS interface used to forward packets for the tunnel ID. */
	uint16_t gre_tunnel_id;
			/**< ID of the tunnel. */
};

/**
 * nss_gre_redir_interface_unmap_msg
 *	Message information for GRE redirect unmapping.
 */
struct nss_gre_redir_interface_unmap_msg {
	uint16_t gre_tunnel_id;		/**< ID of the tunnel. */
};

/**
 * nss_gre_redir_stats_sync_msg
 *	Message information for synchronized GRE redirect statistics.
 */
struct nss_gre_redir_stats_sync_msg {
	struct nss_cmn_node_stats node_stats;	/**< Common node statistics. */
	uint32_t tx_dropped;			/**< Dropped Tx packets. */
};

/**
 * nss_gre_redir_tunnel_stats
 *	GRE redirect statistics as seen by the HLOS.
 */
struct nss_gre_redir_tunnel_stats {
	int if_num;				/**< Interface number for the tunnel. */
	bool valid;				/**< Validity flag for the tunnel. */
	struct nss_cmn_node_stats node_stats;	/**< Common node statistics. */
	uint32_t tx_dropped;			/**< Dropped Tx packets. */
};

/**
 * nss_gre_redir_msg
 *	Data for sending and receiving GRE tunnel redirect messages.
 */
struct nss_gre_redir_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of a GRE tunnel redirect message.
	 */
	union {
		struct nss_gre_redir_configure_msg configure;
				/**< Configure a tunnel. */
		struct nss_gre_redir_interface_map_msg interface_map;
				/**< Map a tunnel ID to an interface number. */
		struct nss_gre_redir_interface_unmap_msg interface_unmap;
				/**< Unmap an interface mapping. */
		struct nss_gre_redir_stats_sync_msg stats_sync;
				/**< Synchronized tunnel statistics. */
	} msg;			/**< Message payload. ??is this comment correct? I assumed it's the message payload because the first field is the message header */
};

/**
 * nss_gre_redir_encap_per_pkt_metadata
 *	Metadata information for an HLOS-to-NSS packet.
 */
struct nss_gre_redir_encap_per_pkt_metadata {
	uint8_t dir;
			/**< Direction in which the packet is forwarded (HLOS to NSS). */
	uint8_t gre_flags;	/**< Flags.??need more info */
	uint8_t gre_prio;	/**< Priority.??need more info */
	uint8_t gre_seq;	/**< Sequence number. */
	uint16_t gre_tunnel_id;	/**< ID of the tunnel. */
	uint8_t ip_dscp;	/**< DSCP values. */

	/**
	 * Override the default DF policy for the packet by setting bit 8.
	 *
	 * The lower 7 bits provide the DF value to be used for this packet.
	 */
	uint8_t ip_df_override;
};

/**
 * nss_gre_redir_decap_per_pkt_metadata
 *	Metadata information for an NSS-to-HLOS packet.
 */
struct nss_gre_redir_decap_per_pkt_metadata {
	uint8_t dir;	/**< Direction in which packet is forwarded (NSS to HLOS). */
	uint8_t gre_flags;	/**< Flags. ??need more info */
	uint8_t gre_prio;	/**< Priority. ??need more info */
	uint8_t gre_seq;	/**< Sequence number. */
	uint16_t gre_tunnel_id;	/**< ID of the tunnel. */
	uint16_t src_if_num;	/**< Number of the source ethernet interface. */
};

/**
 * Callback function for receiving GRE tunnel data.
 *
 * @datatypes
 * net_device \n
 * sk_buff \n
 * napi_struct
 *
 * @param[in] netdev  Pointer to the associated network device.
 * @param[in] skb     Pointer to the data socket buffer.
 * @param[in] napi    Pointer to the NAPI structure.
 */
typedef void (*nss_gre_redir_data_callback_t)(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * Callback function for receiving GRE tunnel messages.
 *
 * @datatypes
 * nss_cmn_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_gre_redir_msg_callback_t)(void *app_data, struct nss_cmn_msg *msg);

/**
 * nss_gre_redir_register_if
 *	Registers the GRE redirect interface with the NSS for sending and receiving
 *	tunnel messages.
 *
 * @datatypes
 * net_device \n
 * nss_gre_redir_data_callback_t \n
 * nss_gre_redir_msg_callback_t
 *
 * @param[in] if_num        NSS interface number.
 * @param[in] dev_ctx       Pointer to the associated network device.
 * @param[in] cb_func_data  Callback for the function data.
 * @param[in] cb_func_msg   Callback for the function message.
 * @param[in] features      Data socket buffer types supported by this interface.
 *
 * @return
 * Pointer to the NSS core context.
 */
extern struct nss_ctx_instance *nss_gre_redir_register_if(uint32_t if_num, struct net_device *dev_ctx,
							nss_gre_redir_data_callback_t cb_func_data,
							nss_gre_redir_msg_callback_t cb_func_msg,
							uint32_t features);

/**
 * nss_gre_redir_unregister_if
 *	Deregisters a GRE tunnel interface from the NSS.
 *
 * @param[in] if_num  NSS interface number.
. *
 * @return
 * None.
 *
 * @dependencies
 * The tunnel interface must have been previously registered.
 */
extern void nss_gre_redir_unregister_if(uint32_t if_num);

/**
 * nss_gre_redir_tx_msg
 *	Sends GRE redirect tunnel messages.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_gre_redir_msg
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 * @param[in]     msg      Pointer to the message data.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_gre_redir_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_gre_redir_msg *msg);

/**
 * nss_gre_redir_tx_buf
 *	Sends GRE redirect tunnel packets for redirection.
 *
 * @datatypes
 * nss_ctx_instance \n
 * sk_buff
 *
 * @param[in,out] nss_ctx  Pointer to the NSS context.
 * @param[in]     os_buf   Pointer to the OS buffer (e.g., skbuff).
 * @param[in]     if_num   Tunnel interface number.
 *
 * @return
 * Status of the Tx operation.
 */
extern nss_tx_status_t nss_gre_redir_tx_buf(struct nss_ctx_instance *nss_ctx, struct sk_buff *os_buf,
						uint32_t if_num);

/**
 * nss_gre_redir_get_stats
 *	Gets GRE redirect tunnel statistics.
 *
 * @datatypes
 * nss_gre_redir_tunnel_stats
 *
 * @param[in]  index  Index in the tunnel statistics array.
 * @param[out] stats  Pointer to the tunnel statistics.
 *
 * @return
 * TRUE or FALSE.
 */
extern bool nss_gre_redir_get_stats(int index, struct nss_gre_redir_tunnel_stats *stats);

/**
 * @}
 */

#endif /* __NSS_GRE_REDIR_H */

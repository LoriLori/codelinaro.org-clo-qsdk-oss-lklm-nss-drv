/*
 **************************************************************************
 * Copyright (c) 2015-2017, The Linux Foundation. All rights reserved.
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
 * @file nss_wifi_vdev.h
 *	NSS TO HLOS Wi-Fi virtual device interface definitions.
 */

#ifndef __NSS_WIFI_VDEV_H
#define __NSS_WIFI_VDEV_H

/**
 * @addtogroup nss_wifi_vdev_subsystem
 * @{
 */

#define NSS_WIFI_HTT_TRANSFER_HDRSIZE_WORD 6	/**< Size of the ??what?. */
#define NSS_WIFI_VDEV_PER_PACKET_METADATA_OFFSET 4
						/**< Per-packet offset of the metadata. ??is this comment correct? */
#define NSS_WIFI_VDEV_DSCP_MAP_LEN 64		/**< Size of the ??what?. */
#define NSS_WIFI_VDEV_IPV6_ADDR_LENGTH 16
		/**< Size of the IPv6 address for the virtual device. ??is this comment correct? */
#define NSS_WIFI_MAX_SRCS 4
		/**< Maximum number of sources. ??is this comment correct? */
#define NSS_WIFI_VDEV_MAX_ME_ENTRIES 32
		/**< Maximum number of multicast enhancement entries. */

/**
 * nss_wifi_vdev_msg_types
 *	Wi-Fi virtual device messages.
 */
enum nss_wifi_vdev_msg_types {
	NSS_WIFI_VDEV_INTERFACE_CONFIGURE_MSG = NSS_IF_MAX_MSG_TYPES + 1,
	NSS_WIFI_VDEV_INTERFACE_UP_MSG,
	NSS_WIFI_VDEV_INTERFACE_DOWN_MSG,
	NSS_WIFI_VDEV_INTERFACE_CMD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_LIST_CREATE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_LIST_DELETE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_ADD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_REMOVE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_UPDATE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_MEMBER_ADD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_LIST_DELETE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_LIST_DUMP_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DUMP_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_RESET_MSG,
	NSS_WIFI_VDEV_SPECIAL_DATA_TX_MSG,
	NSS_WIFI_VDEV_VOW_DBG_CFG_MSG,
	NSS_WIFI_VDEV_VOW_DBG_STATS_REQ_MSG,
	NSS_WIFI_VDEV_DSCP_TID_MAP_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_TOGGLE_MSG,
	NSS_WIFI_VDEV_UPDATECHDR_MSG,
	NSS_WIFI_VDEV_ME_SYNC_MSG,
	NSS_WIFI_VDEV_STATS_MSG,
	NSS_WIFI_VDEV_MAX_MSG
};

/**
 * ??name of enum is missing?
 *	Error types for a Wi-Fi virtual device.
 */
enum {
	NSS_WIFI_VDEV_ENONE,
	NSS_WIFI_VDEV_EUNKNOWN_MSG,
	NSS_WIFI_VDEV_EINV_VID_CONFIG,
	NSS_WIFI_VDEV_EINV_EPID_CONFIG,
	NSS_WIFI_VDEV_EINV_DL_CONFIG,
	NSS_WIFI_VDEV_EINV_CMD,
	NSS_WIFI_VDEV_EINV_ENCAP,
	NSS_WIFI_VDEV_EINV_DECAP,
	NSS_WIFI_VDEV_EINV_RX_NXTN,
	NSS_WIFI_VDEV_EINV_VID_INDEX,
	NSS_WIFI_VDEV_EINV_MC_CFG,
	NSS_WIFI_VDEV_SNOOPTABLE_FULL,
	NSS_WIFI_VDEV_SNOOPTABLE_ENOMEM,
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_UNAVAILABLE,
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_MEMBER_UNAVAILABLE,
	NSS_WIFI_VDEV_SNOOPTABLE_PEER_UNAVAILABLE,
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_ENOMEM,
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_EXIST,
	NSS_WIFI_VDEV_ME_ENOMEM,
	NSS_WIFI_VDEV_EINV_NAWDS_CFG,
	NSS_WIFI_VDEV_EINV_EXTAP_CFG,
	NSS_WIFI_VDEV_EINV_VOW_DBG_CFG,
	NSS_WIFI_VDEV_EINV_DSCP_TID_MAP,
	NSS_WIFI_VDEV_INVALID_ETHER_TYPE,
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_MEMBER_EXIST,
	NSS_WIFI_VDEV_ME_INVALID_NSRCS,
	NSS_WIFI_VDEV_EINV_RADIO_ID,
	NSS_WIFI_VDEV_RADIO_NOT_PRESENT,
	NSS_WIFI_VDEV_CHDRUPD_FAIL,
	NSS_WIFI_VDEV_ME_DENY_GRP_MAX_RCHD,
	NSS_WIFI_VDEV_EINV_MAX_CFG
};

/**
 * nss_wifi_vdev_ext_data_pkt_type
 *	Types of extended data plane packets sent from the NSS to the host.
 */
enum nss_wifi_vdev_ext_data_pkt_type {
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_NONE = 0,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_IGMP = 1,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_MESH = 2,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_INSPECT = 3,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_TXINFO = 4,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_MPSTA_TX = 5,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_MPSTA_RX = 6,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_RX_ERR = 7,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_EXTAP_TX = 8,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_EXTAP_RX = 9,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_WNM_TFS = 10,
	NSS_WIFI_VDEV_EXT_TX_COMPL_PKT_TYPE = 11,
	NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_MAX
};

/**
 * nss_wifi_vdev_cmd
 *	Commands for the Wi-Fi virtual device.
 */
enum nss_wifi_vdev_cmd {
	NSS_WIFI_VDEV_DROP_UNENC_CMD,
	NSS_WIFI_VDEV_ENCAP_TYPE_CMD,
	NSS_WIFI_VDEV_DECAP_TYPE_CMD,
	NSS_WIFI_VDEV_ENABLE_ME_CMD,
	NSS_WIFI_VDEV_NAWDS_MODE_CMD,
	NSS_WIFI_VDEV_EXTAP_CONFIG_CMD,
	NSS_WIFI_VDEV_CFG_BSTEER_CMD,
	NSS_WIFI_VDEV_VOW_DBG_MODE_CMD,
	NSS_WIFI_VDEV_VOW_DBG_RST_STATS_CMD,
	NSS_WIFI_VDEV_CFG_DSCP_OVERRIDE_CMD,
	NSS_WIFI_VDEV_CFG_WNM_CAP_CMD,
	NSS_WIFI_VDEV_CFG_WNM_TFS_CMD,
	NSS_WIFI_VDEV_CFG_WDS_EXT_ENABLE_CMD,
	NSS_WIFI_VDEV_MAX_CMD
};

/**
 * nss_wifi_vdev_config_msg
 *	Virtual device configuration.
 */
struct nss_wifi_vdev_config_msg {
	uint8_t mac_addr[ETH_ALEN];	/**< MAC address. */
	uint16_t radio_ifnum;		/**< Corresponding radio interface number. */
	uint32_t vdev_id;		/**< Virtual device ID. */
	uint32_t epid;			/**< Endpoint ID of the copy engine. */
	uint32_t downloadlen;		/**< Size of the header download. ??needs clarification  what do you mean by "header download"?*/
	uint32_t hdrcachelen;		/**< Size of the header cache. */
	uint32_t hdrcache[NSS_WIFI_HTT_TRANSFER_HDRSIZE_WORD];
			/**< ??Description here. */
	uint32_t opmode;		/**< VAP operating ??operation? mode: AP or station. ??what is AP? */
	uint32_t mesh_mode_en;		/**< Mesh mode is enabled. */
	uint8_t is_mpsta;
			/**< Specifies whether the station is a VAP MP station. ??what is MP? */
	uint8_t is_psta;
			/**< Specifies whether the station is a proxy station. */
	uint8_t special_vap_mode;
			/**< Special VAP for monitoring received management packets. */
	uint8_t smartmesh_mode_en;
			/**< VAP is configured as a smart monitor VAP. */
};

/**
 * nss_wifi_vdev_enable_msg
 *	Enable a message for a virtual device.
 */
struct nss_wifi_vdev_enable_msg {
	uint8_t mac_addr[ETH_ALEN];	/**< MAC address. */
	uint8_t reserved[2];		/**< Reserved ??for 4-byte alignment padding?. */
};

/**
 * nss_wifi_vdev_disable_msg
 *	Disable message for a virtual device.
 */
struct nss_wifi_vdev_disable_msg {
	uint32_t reserved;		/**< Placeholder for ??. */
};

/**
 * nss_wifi_vdev_cmd_msg
 *	Virtual device commands.
 */
struct nss_wifi_vdev_cmd_msg {
	uint32_t cmd;			/**< Command type. */
	uint32_t value;			/**< Command value. */
};

/**
 * nss_wifi_vdev_me_snptbl_grp_create_msg
 *	Information for creating the snooptable group of a virtual device.
 */
struct nss_wifi_vdev_me_snptbl_grp_create_msg {
	uint32_t ether_type;		/**< Ether type of the multicast group. */

	/**
	 * IP address of a multicast group.
	 */
	union {
		uint32_t grpaddr_ip4;
				/**< IPv4 address. */
		uint8_t grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
				/**< IPv6 address. */
	} u;			/**< IP address of the multicast group. */

	uint8_t grp_addr[ETH_ALEN];	/**< MAC address of the multicast group. */
};

/**
 * nss_wifi_vdev_me_snptbl_grp_delete_msg
 *	Information for deleting a snooplist group list.
 */
struct nss_wifi_vdev_me_snptbl_grp_delete_msg {
	uint32_t ether_type;		/**< Ether type of the multicast group. */

	/**
	 * IP address of the multicast group.
	 */
	union {
		uint32_t grpaddr_ip4;
				/**< IPv4 address. */
		uint8_t grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
				/**< IPv6 address. */
	} u;			/**< IP address of the multicast group. */

	uint8_t grp_addr[ETH_ALEN];	/**< MAC address of the multicast group. */
};

/**
 * nss_wifi_vdev_me_snptbl_grp_mbr_add_msg
 *	Information for adding a snooplist group member.
 */
struct nss_wifi_vdev_me_snptbl_grp_mbr_add_msg {
	uint32_t ether_type;		/**< Ether type of the multicast group. */

	/**
	 * IP address of the multicast group.
	 */
	union {
		uint32_t grpaddr_ip4;
				/**< IPv4 address. */
		uint8_t grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
				/**< IPv6 address. */
	} u;			/**< IP address of the multicast group. */

	uint32_t peer_id;		/**< Peer ID. */
	uint8_t grp_addr[ETH_ALEN];	/**< MAC address of the multicast group. */
	uint8_t grp_member_addr[ETH_ALEN];
		/**< MAC address of the multicast group member. */
	uint8_t mode;
		/**< Mode. ??need more information - e.g., what type of mode?*/
	uint8_t nsrcs;
		/**< Number of source IP addresses for SSM. ??what is SSM */
	uint8_t src_ip_addr[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH * NSS_WIFI_MAX_SRCS];
		/**< Source IP address. */
};

/**
 * nss_wifi_vdev_me_snptbl_grp_mbr_delete_msg
 *	Information for removing a snooplist group member.
 */
struct nss_wifi_vdev_me_snptbl_grp_mbr_delete_msg {
	uint32_t ether_type;		/**< Ether type of the multicast group. */

	/**
	 * IP address of the multicast group.
	 */
	union {
		uint32_t grpaddr_ip4;
				/**< IPv4 address. */
		uint8_t grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
				/**< IPv6 address. */
	}u;			/**< IP address of the multicast group. */

	uint8_t grp_addr[ETH_ALEN];
			/**< MAC address of the multicast group. */
	uint8_t grp_member_addr[ETH_ALEN];
			/**< MAC address of the multicast group member. */
};

/**
 * nss_wifi_vdev_me_snptbl_grp_mbr_update_msg
 *	Information for updating a snooplist group member.
 */
struct nss_wifi_vdev_me_snptbl_grp_mbr_update_msg {
	uint32_t ether_type;	/**< Ether type of the multicast group. */

	/**
	 * IP address of the multicast group.
	 */
	union {
		uint32_t grpaddr_ip4;
				/**< IPv4 address. */
		uint8_t grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
				/**< IPv6 address. */
	}u;			/**< IP address of the multicast group. */

	uint8_t grp_addr[ETH_ALEN];	/**< MAC address of the multicast group. */
	uint8_t grp_member_addr[ETH_ALEN];
			/**< MAC address of the multicast group member. */
	uint8_t mode;	/**< Mode. ??need more information; e.g., what type of mode */
	uint8_t nsrcs;	/**< Number of source IP addresses for SSM. ??spell SSM */
	uint8_t src_ip_addr[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH * NSS_WIFI_MAX_SRCS];
			/**< Source IP address. */
};

/**
 * nss_wifi_vdev_me_snptbl_deny_grp_add_msg
 *	Information for adding a snooplist member to a deny list.
 */
struct nss_wifi_vdev_me_snptbl_deny_grp_add_msg {
	uint32_t grpaddr;	/**< IP address of the multicast group. */
};

/**
 * nss_wifi_vdev_txmsg
 *	Information for transmitting special data.
 */
struct nss_wifi_vdev_txmsg {
	uint16_t peer_id;	/**< Peer ID. */
	uint16_t tid;		/**< Traffic ID. */
};

/**
 * nss_wifi_vdev_vow_dbg_stats
 *	Types of VoW debug statistics.
 */
struct nss_wifi_vdev_vow_dbg_stats {
	uint32_t rx_vow_dbg_counters;		/**< VoW Rx debug counter. */
	uint32_t tx_vow_dbg_counters[8];	/**< VoW Tx debug counter. */
};

/**
 * nss_wifi_vdev_vow_dbg_cfg_msg
 *	Information for configuring VoW debug statistics.
 */
struct nss_wifi_vdev_vow_dbg_cfg_msg {
	uint8_t vow_peer_list_idx;	/**< Index of the peer list. */
	uint8_t tx_dbg_vow_peer_mac4;	/**< MAC address 4 for the peer. ??is this comment correct? */
	uint8_t tx_dbg_vow_peer_mac5;	/**< MAC address 5 for the peer. ??is this comment correct? */
};

/**
 * nss_wifi_vdev_dscp_tid_map
 *	DSCP-to-TID mapping.
 */
struct nss_wifi_vdev_dscp_tid_map {
	uint32_t dscp_tid_map[NSS_WIFI_VDEV_DSCP_MAP_LEN];
		/**< Array holding the DSCP-to-TID mapping. */
};

/**
 * nss_wifi_vdev_igmp_per_packet_metadata
 *	Per-packet metadata for IGMP packets.
 */
struct nss_wifi_vdev_igmp_per_packet_metadata {
	uint32_t tid;				/**< Traffic ID. */
	uint32_t tsf32;				/**< TSF value.??what is TSF? */
	uint8_t peer_mac_addr[ETH_ALEN];	/**< Peer MAC address. */
	uint8_t reserved[2];			/**< Reserved ??for 4 byte-alignment?. */
};

/**
 * nss_wifi_vdev_mesh_per_packet_metadata
 *	Per-packet metadata for Mesh packets.
 */
struct nss_wifi_vdev_mesh_per_packet_metadata {
	uint32_t status;	/**< Status. ??need more info; status of what? */
	uint32_t rssi;		/**< Rssi. ??need more info; what is RSSI? */
};

/**
 * nss_wifi_vdev_txinfo_per_packet_metadata
 *	Per-packet metadata for Tx completion information packets.
 */
struct nss_wifi_vdev_txinfo_per_packet_metadata {
	uint32_t status;		/**< Tx completion status. */
	uint16_t msdu_count;		/**< Count of MSDUs in the MSDU list. ??what is the diff between msdu_count and num_msdu? Count and number of typically mean the same thing. */
	uint16_t num_msdu;		/**< Number of MSDUs in the MSDU list. */
	uint32_t msdu_q_time;		/**< Time spent by an MSDU in the Wi-Fi firmware. */
	uint32_t ppdu_rate;			/**< PPDU rate in ratecode. ??what is ratecode?*/
	uint8_t ppdu_num_mpdus_success;		/**< Number of successful 8-bit MPDUs. ??is this comment correct? */
	uint8_t ppdu_num_mpdus_fail;		/**< Number of failed 8-bit MPDUs. ??is this comment correct? */
	uint16_t ppdu_num_msdus_success;	/**< Number of successful 16-bit MSDUs. ??is this comment correct? */
	uint32_t ppdu_bytes_success;	/**< Number of successful bytes. */
	uint32_t ppdu_duration;		/**< Estimated air time. */
	uint8_t ppdu_retries;		/**< Number of times a PPDU is retried. ??if a PPDU is a data unit, this sentence doesn't make sense; please clarify. */
	uint8_t ppdu_is_aggregate;	/**< Flag to check whether a PPDU is aggregated. */
	uint16_t start_seq_num;		/**< Starting MSDU ID for this PPDU. */
	uint16_t version;		/**< PPDU statistics version. */
	uint32_t ppdu_ack_timestamp;
			/**< Timestamp(in ms) when an acknowledgement was received. */
	uint32_t ppdu_bmap_enqueued_lo;
			/**< Bitmap of packets enqueued to the hardware (LSB). */
	uint32_t ppdu_bmap_enqueued_hi;
			/**< Bitmap of packets enqueued to the hardware (MSB). */
	uint32_t ppdu_bmap_tried_lo;
			/**< Bitmap of packets sent over the air (LSB). */
	uint32_t ppdu_bmap_tried_hi;
			/**< Bitmap of packets sent over the air (MSB). */
	uint32_t ppdu_bmap_failed_lo;
			/**< Bitmap of packets that failed to be acknowledged (LSB). */
	uint32_t ppdu_bmap_failed_hi;
			/**< Bitmap of packets that failed to be acknowledged (MSB). */
};

/**
 * nss_wifi_vdev_qwrap_tx_metadata_types
 *	Per-packet metadata types for Qwrap Tx packets.??what is qwrap
 */
enum nss_wifi_vdev_qwrap_tx_metadata_types {
	NSS_WIFI_VDEV_QWRAP_TYPE_NONE = 0,
	NSS_WIFI_VDEV_QWRAP_TYPE_TX = 1,
	NSS_WIFI_VDEV_QWRAP_TYPE_RX_TO_TX = 2
};

/**
 * nss_wifi_vdev_extap_pkt_types
 *	Per-packet metadata types for ExtAP Tx packets.
 */
enum nss_wifi_vdev_extap_pkt_types {
	NSS_WIFI_VDEV_EXTAP_PKT_TYPE_NONE = 0,
	NSS_WIFI_VDEV_EXTAP_PKT_TYPE_TX = 1,
	NSS_WIFI_VDEV_EXTAP_PKT_TYPE_RX_TO_TX = 2
};

/**
 * nss_wifi_vdev_mpsta_per_packet_tx_metadata
 *	Per-packet metadata for transmitting packets to an MP station.
 */
struct nss_wifi_vdev_mpsta_per_packet_tx_metadata {
	uint16_t vdev_id;		/**< Virtual device ID. */
	uint16_t metadata_type;		/**< Tx metadata type. */
};

/**
 * nss_wifi_vdev_mpsta_per_packet_rx_metadata
 *	Per-packet metadata for receiving packets from an mp station.
 */
struct nss_wifi_vdev_mpsta_per_packet_rx_metadata {
	uint16_t vdev_id;		/**< Virtual device ID. */
	uint16_t peer_id;		/**< Peer ID. */
};

/*
 * nss_wifi_vdev_rx_err_per_packet_metadata
 *	Per-packet metadata for error packets received.
 */
struct nss_wifi_vdev_rx_err_per_packet_metadata {
	uint8_t peer_mac_addr[ETH_ALEN];	/*< Peer MAC address. */
	uint8_t tid;				/*< Traffic ID. */
	uint8_t vdev_id;			/*< Virtual device ID. */
	uint8_t err_type;			/*< Error type. */
	uint8_t rsvd[3];			/*< Reserved ??for ?-byte alignment. */
};

/*
 * nss_wifi_vdev_extap_per_packet_metadata
 *	Per-packet metadata for ExtAP.
 */
struct nss_wifi_vdev_extap_per_packet_metadata {
	uint16_t pkt_type;	/**< ExtAP packet type. */
	uint8_t res[2];		/**< Reserved for 4-byte alignment. ??is this comment correct? */
};

/**
 * nss_wifi_vdev_tx_compl_metadata
 *	Per-packet metadata for Tx complete. ??what do you mean by "Tx complete"?
 */
struct nss_wifi_vdev_tx_compl_metadata {
	uint8_t ta[ETH_ALEN];	/**< Transmitter MAC address. */
	uint8_t ra[ETH_ALEN];	/**< Receiver MAC address. */
	uint16_t ppdu_id;	/**< PPDU ID. */
	uint16_t peer_id;	/**< Peer ID. */
};

/**
 * nss_wifi_vdev_per_packet_metadata
 *	Payload of per-packet metadata.
 */
struct nss_wifi_vdev_per_packet_metadata {
	uint32_t pkt_type;	/**< Type of packet. */

	/**
	 * ??Description here for the union section in the PDF.
	 */
	union {
		struct nss_wifi_vdev_igmp_per_packet_metadata igmp_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_mesh_per_packet_metadata mesh_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_txinfo_per_packet_metadata txinfo_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_mpsta_per_packet_tx_metadata mpsta_tx_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_mpsta_per_packet_rx_metadata mpsta_rx_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_rx_err_per_packet_metadata rx_err_metadata;
			/**< ??Description here. */
		struct nss_wifi_vdev_tx_compl_metadata tx_compl_metadata;
			/**< ??Description here. */
	} metadata;	/**< ??Description here for the union in the parent struct table row in the PDF. */
};

/**
 * nss_wifi_vdev_meshmode_rx_metadata
 *	Metadata for receiving the Mesh mode. ??is this comment correct?
 */
struct nss_wifi_vdev_meshmode_rx_metadata {
	uint16_t vdev_id;	/**< Virtual device ID. */
	uint16_t peer_id;	/**< Peer ID. */
};

/**
 * nss_wifi_vdev_rawmode_rx_metadata
 *	Metadata for receiving the Raw mode. ??is this comment correct?
 */
struct nss_wifi_vdev_rawmode_rx_metadata {
	uint16_t vdev_id;	/**< Virtual device ID. */
	uint16_t peer_id;	/**< Peer ID. */
};

/**
 * nss_wifi_vdev_updchdr_msg
 *	Information for updating a cache header.
 */
struct nss_wifi_vdev_updchdr_msg {
	uint32_t hdrcache[NSS_WIFI_HTT_TRANSFER_HDRSIZE_WORD];
				/**< Updated header cache. */
	uint32_t vdev_id;	/**< Virtual device ID. */
};

/**
 * nss_wifi_vdev_me_host_sync_grp_entry
 *	Multicast enhancement host synchronization group table. ??needs clarification?
 */
struct nss_wifi_vdev_me_host_sync_grp_entry {
	uint8_t group_addr[ETH_ALEN];		/**< Group address for this list. */
	uint8_t grp_member_addr[ETH_ALEN];	/**< MAC address of the multicast group member. */

	/**
	 * Type of group addresses. ??is this comment correct?
	 */
	union {
		uint32_t grpaddr_ip4;
			/**< IPv4 group address. ??is this comment correct? */
		uint8_t  grpaddr_ip6[NSS_WIFI_VDEV_IPV6_ADDR_LENGTH];
			/**< IPv6 group address. ??is this comment correct? */
	} u;	/**< Type of group addresses. ??is this comment correct? */

	uint32_t src_ip_addr;			/**< Source IP address. */
};

/**
 * wifi_vdev_me_host_sync_msg
 *	Synchronization message for a multicast enhancement host group. ??is this comment correct?
 */
struct nss_wifi_vdev_me_host_sync_msg {
	uint16_t vdev_id;	/**< Virtual device ID. */
	uint8_t nentries;	/**< Number of group entries carried by this message. */
	uint8_t radio_ifnum;	/**< Interface number of the Wi-Fi radio. */
	struct nss_wifi_vdev_me_host_sync_grp_entry grp_entry[NSS_WIFI_VDEV_MAX_ME_ENTRIES];	/**< Maximum number of synchronized group entries. ??is this comment correct? */
};

/**
 * nss_wifi_vdev_mcast_enhance_stats
 *	Multicast enhancement-related statistics.
 */
struct nss_wifi_vdev_mcast_enhance_stats {

	/**
	 * Number of multicast packets recieved for multicast enhancement conversion.
	 */
	uint32_t mcast_rcvd;

	/**
	 * Number of unicast packets sent as part of multicast enhancement conversion.
	 */
	uint32_t mcast_ucast_converted;

	/**
	 * Number of multicast enhancement frames dropped because of a
	 * buffer allocation failure.
	 */
	uint32_t mcast_alloc_fail;

	/**
	 * Number of multicast enhancement frames dropped because of a
	 * buffer enqueue failure.
	 */
	uint32_t mcast_pbuf_enq_fail;

	/**
	 * Number of multicast enhancement frames dropped because of a
	 * buffer copy failure.
	 */
	uint32_t mcast_pbuf_copy_fail;

	/**
	 * Number of multicast enhancement frames dropped because of a
	 * failure in sending flow control to a peer.
	 */
	uint32_t mcast_peer_flow_ctrl_send_fail;

	/**
	 * Number of multicast enhancement buffer frames dropped when
	 * destination MAC is the same as source MAC.
	 */
	uint32_t mcast_loopback_err;

	/**
	 * Number of multicast enhancement buffer frames dropped
	 * because of an empty destination MAC.
	 */
	uint32_t mcast_dst_address_err;

	/**
	 * Number of multicast enhancement buffer frames dropped
	 * because no member is listening on the group.
	 */
	uint32_t mcast_no_enhance_drop_cnt;
};

/**
 * nss_wifi_vdev_stats_sync_msg
 *	Synchronization message for virtual device statistics. ??is this comment correct?
 */
struct nss_wifi_vdev_stats_sync_msg {
	uint32_t dropped;	/**< Number of dropped packets. */
	struct nss_wifi_vdev_mcast_enhance_stats wvmes;
				/**< Multicast enhancement statistics. */
};

/**
 * nss_wifi_vdev_msg
 *	Data for sending and receiving virtual device-specific messages.
 */
struct nss_wifi_vdev_msg {
	struct nss_cmn_msg cm;		/**< Common message header. */

	/**
	 * Payload of a virtual device-specific message.
	 ??I tried to create descriptions for the following union members; please verify.
	 */
	union {
		struct nss_wifi_vdev_config_msg vdev_config;
				/**< Virtual device configuration. */
		struct nss_wifi_vdev_enable_msg vdev_enable;
				/**< Enable a message for a virtual device. */
		struct nss_wifi_vdev_cmd_msg vdev_cmd;
				/**< Command message for a virtual device. */
		struct nss_wifi_vdev_me_snptbl_grp_create_msg vdev_grp_list_create;
				/**< Creates the snooptable group of a virtual device. */
		struct nss_wifi_vdev_me_snptbl_grp_delete_msg vdev_grp_list_delete;
				/**< Deletes a snooplist group list. */
		struct nss_wifi_vdev_me_snptbl_grp_mbr_add_msg vdev_grp_member_add;
				/**< Adds a snooplist group member. */
		struct nss_wifi_vdev_me_snptbl_grp_mbr_delete_msg vdev_grp_member_remove;
				/**< Removes a snooplist group member. */
		struct nss_wifi_vdev_me_snptbl_grp_mbr_update_msg vdev_grp_member_update;
				/**< Updates a snooplist group member. */
		struct nss_wifi_vdev_me_snptbl_deny_grp_add_msg vdev_deny_member_add;
				/**< Adds a snooplist member to a deny list. */
		struct nss_wifi_vdev_txmsg vdev_txmsgext;
				/**< Transmits special data. */
		struct nss_wifi_vdev_vow_dbg_cfg_msg vdev_vow_dbg_cfg;
				/**< Configures VoW debug statistics. */
		struct nss_wifi_vdev_vow_dbg_stats vdev_vow_dbg_stats;
				/**< Types of VoW debug statistics. */
		struct nss_wifi_vdev_dscp_tid_map vdev_dscp_tid_map;
				/**< DSCP-to-TID mapping. */
		struct nss_wifi_vdev_updchdr_msg vdev_updchdr;
				/**< Updates a cache header. */
		struct nss_wifi_vdev_me_host_sync_msg vdev_me_sync;
				/**< Synchronization message for a multicast enhancement host group. ??is this comment correct? */
		struct nss_wifi_vdev_stats_sync_msg vdev_stats;
				/**< Synchronization message for virtual device statistics. ??is this comment correct? */
	} msg;		/**< Message payload. ??is this comment correct? I assumed it's the message payload because the first field is the message header */
};

/**
 * nss_wifi_vdev_tx_msg
 *	Sends a Wi-Fi message to the NSS interface.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_wifi_vdev_msg
 *
 * @param[in,out] nss_ctx  Pointer to the NSS core context.
 * @param[in]     msg      Pointer to the message data.
 *
 * @return
 * Status of the Tx operation.
 */
nss_tx_status_t nss_wifi_vdev_tx_msg(struct nss_ctx_instance *nss_ctx,
				struct nss_wifi_vdev_msg *msg);

/**
 * nss_wifi_vdev_tx_buf
 *	Sends a Wi-Fi data packet to the NSS interface.
 *
 * @datatypes
 * nss_ctx_instance \n
 * sk_buff
 *
 * @param[in,out] nss_ctx  Pointer to the NSS core context.
 * @param[in]     os_buf   Pointer to the OS data buffer.
 * @param[in]     if_num   NSS interface number.
 *
 * @return
 * Status of the Tx operation.
 */
nss_tx_status_t nss_wifi_vdev_tx_buf(struct nss_ctx_instance *nss_ctx,
				struct sk_buff *os_buf, uint32_t if_num);

/**
 * Callback function for receiving Wi-Fi virtual device messages.
 *
 * @datatypes
 * nss_cmn_msg
 *
 * @param[in] app_data  Pointer to the application context of the message.
 * @param[in] msg       Pointer to the message data.
 */
typedef void (*nss_wifi_vdev_msg_callback_t)(void *app_data,
					struct nss_cmn_msg *msg);

/**
 * Callback function for receiving Wi-Fi virtual device data.
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
typedef void (*nss_wifi_vdev_callback_t)(struct net_device *netdev,
				struct sk_buff *skb, struct napi_struct *napi);

/**
 * Callback function for receiving extended data plane Wi-Fi virtual device data.
 *
 * @datatypes
 * net_device \n
 * sk_buff \n
 * napi_struct
 *
 * @param[in] netdev  Pointer to the associated network device.
 * @param[in] skb     Pointer to the data socket buffer.
 * @param[in] napi    Pointer to the NAPI structure.
 * @param[in] netdev  Pointer to the associated network device.
 */
typedef void (*nss_wifi_vdev_ext_data_callback_t)(struct net_device *netdev,
				struct sk_buff *skb, struct napi_struct *napi);

/**
 * nss_wifi_vdev_msg_init
 *	Initializes a Wi-Fi virtual device message.
 *
 * @datatypes
 * nss_wifi_vdev_msg \n
 * nss_wifi_vdev_msg_callback_t
 *
 * @param[in] nim       Pointer to the NSS interface message.
 * @param[in] if_num    NSS interface number.
 * @param[in] type      Type of message.
 * @param[in] len       Length of message.
 * @param[in] cb        Message callback.
 * @param[in] app_data  Pointer to the application context of the message.
 *
 * @return
 * None.
 */
void nss_wifi_vdev_msg_init(struct nss_wifi_vdev_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
				nss_wifi_vdev_msg_callback_t *cb, void *app_data);

/**
 * nss_register_wifi_vdev_if
 *	Registers a Wi-Fi virtual device interface with the NSS interface.
 *
 * @datatypes
 * nss_ctx_instance \n
 * nss_wifi_vdev_callback_t \n
 * nss_wifi_vdev_ext_data_callback_t \n
 * nss_wifi_vdev_msg_callback_t \n
 * net_device
 *
 * @param[in,out] nss_ctx                 Pointer to the NSS core context.
 * @param[in]     if_num                  NSS interface number.
 * @param[in]     wifi_data_callback      Callback for the Wi-Fi virtual device data.
 * @param[in]     vdev_ext_data_callback  Callback for the extended data.
 * @param[in]     wifi_event_callback     Callback for the message.
 * @param[in]     netdev                  Pointer to the associated network device.
 * @param[in]     features                Data socket buffer types supported by this
 *                                        interface.
 *
 * @return
 * None.
 */
uint32_t nss_register_wifi_vdev_if(struct nss_ctx_instance *nss_ctx, int32_t if_num, nss_wifi_vdev_callback_t wifi_data_callback,
			nss_wifi_vdev_ext_data_callback_t vdev_ext_data_callback, nss_wifi_vdev_msg_callback_t wifi_event_callback,
			struct net_device *netdev, uint32_t features);

/**
 * nss_unregister_wifi_vdev_if
 *	Deregisters a Wi-Fi virtual device interface from the NSS interface.
 *
 * @param[in] if_num  NSS interface number.
 *
 * @return
 * None.
 */
void nss_unregister_wifi_vdev_if(uint32_t if_num);

/**
 * nss_wifi_vdev_tx_msg_ext
 *	Sends Wi-Fi data packet along with metadata as message to the NSS.
 *
 * @datatypes
 * nss_ctx_instance \n
 * sk_buff
 *
 * @param[in,out] nss_ctx  Pointer to the NSS core context.
 * @param[in]     os_buf   Pointer to the OS data buffer.
 *
 * @return
 * Status of the Tx operation.
 */
nss_tx_status_t nss_wifi_vdev_tx_msg_ext(struct nss_ctx_instance *nss_ctx, struct sk_buff *os_buf);

/**
 * @}
 */

#endif /* __NSS_WIFI_VDEV_H */

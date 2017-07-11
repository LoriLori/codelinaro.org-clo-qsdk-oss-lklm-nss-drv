/*
 **************************************************************************
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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

#include "nss_ppe.h"

static uint8_t ppe_cc_nonexception[NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_MAX] = {
	NSS_STATS_PPE_CPU_CODE_EXP_FAKE_L2_PROT_ERR,
	NSS_STATS_PPE_CPU_CODE_EXP_FAKE_MAC_HEADER_ERR,
	NSS_STATS_PPE_CPU_CODE_EXP_BITMAP_MAX,
	NSS_STATS_PPE_CPU_CODE_L2_EXP_MRU_FAIL,
	NSS_STATS_PPE_CPU_CODE_L2_EXP_MTU_FAIL,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_IP_PREFIX_BC,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_MTU_FAIL,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_MRU_FAIL,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_ICMP_RDT,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_IP_RT_TTL1_TO_ME,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_IP_RT_TTL_ZERO,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_SERVICE_CODE_LOOP,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_DE_ACCELERATE,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_FLOW_SRC_IF_CHK_FAIL,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_SYNC_TOGGLE_MISMATCH,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_MTU_DF_FAIL,
	NSS_STATS_PPE_CPU_CODE_L3_EXP_PPPOE_MULTICAST,
	NSS_STATS_PPE_CPU_CODE_MGMT_OFFSET,
	NSS_STATS_PPE_CPU_CODE_MGMT_EAPOL,
	NSS_STATS_PPE_CPU_CODE_MGMT_PPPOE_DIS,
	NSS_STATS_PPE_CPU_CODE_MGMT_IGMP,
	NSS_STATS_PPE_CPU_CODE_MGMT_ARP_REQ,
	NSS_STATS_PPE_CPU_CODE_MGMT_ARP_REP,
	NSS_STATS_PPE_CPU_CODE_MGMT_DHCPv4,
	NSS_STATS_PPE_CPU_CODE_MGMT_MLD,
	NSS_STATS_PPE_CPU_CODE_MGMT_NS,
	NSS_STATS_PPE_CPU_CODE_MGMT_NA,
	NSS_STATS_PPE_CPU_CODE_MGMT_DHCPv6,
	NSS_STATS_PPE_CPU_CODE_PTP_OFFSET,
	NSS_STATS_PPE_CPU_CODE_PTP_SYNC,
	NSS_STATS_PPE_CPU_CODE_PTP_FOLLOW_UP,
	NSS_STATS_PPE_CPU_CODE_PTP_DELAY_REQ,
	NSS_STATS_PPE_CPU_CODE_PTP_DELAY_RESP,
	NSS_STATS_PPE_CPU_CODE_PTP_PDELAY_REQ,
	NSS_STATS_PPE_CPU_CODE_PTP_PDELAY_RESP,
	NSS_STATS_PPE_CPU_CODE_PTP_PDELAY_RESP_FOLLOW_UP,
	NSS_STATS_PPE_CPU_CODE_PTP_ANNOUNCE,
	NSS_STATS_PPE_CPU_CODE_PTP_MANAGEMENT,
	NSS_STATS_PPE_CPU_CODE_PTP_SIGNALING,
	NSS_STATS_PPE_CPU_CODE_PTP_PKT_RSV_MSG,
	NSS_STATS_PPE_CPU_CODE_IPV4_SG_UNKNOWN,
	NSS_STATS_PPE_CPU_CODE_IPV6_SG_UNKNOWN,
	NSS_STATS_PPE_CPU_CODE_ARP_SG_UNKNOWN,
	NSS_STATS_PPE_CPU_CODE_ND_SG_UNKNOWN,
	NSS_STATS_PPE_CPU_CODE_IPV4_SG_VIO,
	NSS_STATS_PPE_CPU_CODE_IPV6_SG_VIO,
	NSS_STATS_PPE_CPU_CODE_ARP_SG_VIO,
	NSS_STATS_PPE_CPU_CODE_ND_SG_VIO,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTING_IP_TO_ME,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_SNAT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_DNAT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_RT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_BR_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_MC_BRIDGE_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_PREHEAD_RT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_PREHEAD_SNAPT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_PREHEAD_DNAPT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_PREHEAD_SNAT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_PREHEAD_DNAT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_NO_ROUTE_PREHEAD_NAT_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_NO_ROUTE_PREHEAD_NAT_ERROR,
	NSS_STATS_PPE_CPU_CODE_L3_ROUTE_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_NO_ROUTE_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_NO_ROUTE_NH_INVALID_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_NO_ROUTE_PREHEAD_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_BRIDGE_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_ACTION,
	NSS_STATS_PPE_CPU_CODE_L3_FLOW_MISS_ACTION,
	NSS_STATS_PPE_CPU_CODE_L2_NEW_MAC_ADDRESS,
	NSS_STATS_PPE_CPU_CODE_L2_HASH_COLLISION,
	NSS_STATS_PPE_CPU_CODE_L2_STATION_MOVE,
	NSS_STATS_PPE_CPU_CODE_L2_LEARN_LIMIT,
	NSS_STATS_PPE_CPU_CODE_L2_SA_LOOKUP_ACTION,
	NSS_STATS_PPE_CPU_CODE_L2_DA_LOOKUP_ACTION,
	NSS_STATS_PPE_CPU_CODE_APP_CTRL_ACTION,
	NSS_STATS_PPE_CPU_CODE_IN_VLAN_FILTER_ACTION,
	NSS_STATS_PPE_CPU_CODE_IN_VLAN_XLT_MISS,
	NSS_STATS_PPE_CPU_CODE_EG_VLAN_FILTER_DROP,
	NSS_STATS_PPE_CPU_CODE_ACL_PRE_ACTION,
	NSS_STATS_PPE_CPU_CODE_ACL_POST_ACTION,
	NSS_STATS_PPE_CPU_CODE_SERVICE_CODE_ACTION,
};

/*
 * nss_ppe_verify_ifnum()
 *	Verify PPE interface number.
 */
static inline bool nss_ppe_verify_ifnum(int if_num)
{
	return nss_is_dynamic_interface(if_num) || (if_num == NSS_PPE_INTERFACE);
}

/*
 * nss_ppe_stats_sync
 *	PPE connection sync stats from NSS
 */
static void nss_ppe_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_ppe_sync_stats_msg *stats_msg, uint16_t if_num)
{
	spin_lock_bh(&nss_ppe_stats_lock);
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_L3_FLOWS] += stats_msg->nss_ppe_v4_l3_flows;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_L2_FLOWS] += stats_msg->nss_ppe_v4_l2_flows;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_CREATE_REQ] += stats_msg->nss_ppe_v4_create_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_CREATE_FAIL] += stats_msg->nss_ppe_v4_create_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_DESTROY_REQ] += stats_msg->nss_ppe_v4_destroy_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_DESTROY_FAIL] += stats_msg->nss_ppe_v4_destroy_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_CREATE_REQ] += stats_msg->nss_ppe_v4_mc_create_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_CREATE_FAIL] += stats_msg->nss_ppe_v4_mc_create_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_UPDATE_REQ] += stats_msg->nss_ppe_v4_mc_update_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_UPDATE_FAIL] += stats_msg->nss_ppe_v4_mc_update_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_DESTROY_REQ] += stats_msg->nss_ppe_v4_mc_destroy_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V4_MC_DESTROY_FAIL] += stats_msg->nss_ppe_v4_mc_destroy_fail;

	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_L3_FLOWS] += stats_msg->nss_ppe_v6_l3_flows;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_L2_FLOWS] += stats_msg->nss_ppe_v6_l2_flows;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_CREATE_REQ] += stats_msg->nss_ppe_v6_create_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_CREATE_FAIL] += stats_msg->nss_ppe_v6_create_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_DESTROY_REQ] += stats_msg->nss_ppe_v6_destroy_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_DESTROY_FAIL] += stats_msg->nss_ppe_v6_destroy_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_CREATE_REQ] += stats_msg->nss_ppe_v6_mc_create_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_CREATE_FAIL] += stats_msg->nss_ppe_v6_mc_create_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_UPDATE_REQ] += stats_msg->nss_ppe_v6_mc_update_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_UPDATE_FAIL] += stats_msg->nss_ppe_v6_mc_update_fail;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_DESTROY_REQ] += stats_msg->nss_ppe_v6_mc_destroy_req;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_V6_MC_DESTROY_FAIL] += stats_msg->nss_ppe_v6_mc_destroy_fail;

	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_VP_FULL] += stats_msg->nss_ppe_fail_vp_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_NH_FULL] += stats_msg->nss_ppe_fail_nh_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_FLOW_FULL] += stats_msg->nss_ppe_fail_flow_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_HOST_FULL] += stats_msg->nss_ppe_fail_host_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_PUBIP_FULL] += stats_msg->nss_ppe_fail_pubip_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_PORT_SETUP] += stats_msg->nss_ppe_fail_port_setup;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_RW_FIFO_FULL] += stats_msg->nss_ppe_fail_rw_fifo_full;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_FLOW_COMMAND] += stats_msg->nss_ppe_fail_flow_command;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_UNKNOWN_PROTO] += stats_msg->nss_ppe_fail_unknown_proto;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_PPE_UNRESPONSIVE] += stats_msg->nss_ppe_fail_ppe_unresponsive;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_CE_OPAQUE_INVALID] += stats_msg->nss_ppe_ce_opaque_invalid;
	nss_ppe_debug_stats.conn_stats[NSS_STATS_PPE_FAIL_FQG_FULL] += stats_msg->nss_ppe_fail_fqg_full;
	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_stats_conn_get()
 *	Get ppe connection stats.
 */
void nss_ppe_stats_conn_get(uint32_t *stats)
{
	if (!stats) {
		nss_warning("No memory to copy ppe connection stats");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);

	if (!nss_ppe_debug_stats.valid) {
		spin_unlock_bh(&nss_ppe_stats_lock);
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	/*
	 * Get flow stats
	 */
	memcpy(stats, nss_ppe_debug_stats.conn_stats, (sizeof(uint32_t) * NSS_STATS_PPE_CONN_MAX));

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_stats_l3_get()
 *	Get ppe L3 debug stats.
 */
void nss_ppe_stats_l3_get(uint32_t *stats)
{
	if (!stats) {
		nss_warning("No memory to copy ppe l3 dbg stats\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);

	if (!nss_ppe_debug_stats.valid) {
		spin_unlock_bh(&nss_ppe_stats_lock);
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG0_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_0]);

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG1_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_1]);

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG2_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_2]);

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG3_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_3]);

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG4_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_4]);

	nss_ppe_reg_write(PPE_L3_DBG_WR_OFFSET, PPE_L3_DBG_PORT_OFFSET);
	nss_ppe_reg_read(PPE_L3_DBG_RD_OFFSET, &stats[NSS_STATS_PPE_L3_DBG_PORT]);

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_stats_code_get()
 *	Get ppe CPU and DROP code for last packet processed.
 */
void nss_ppe_stats_code_get(uint32_t *stats)
{
	uint32_t drop_0, drop_1, cpu_code;

	nss_trace("%s(%d) Start\n", __func__, __LINE__);
	if (!stats) {
		nss_warning("No memory to copy ppe code\n");
		return;
	}

	if (!nss_ppe_debug_stats.valid) {
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);
	nss_ppe_reg_write(PPE_PKT_CODE_WR_OFFSET, PPE_PKT_CODE_DROP0_OFFSET);
	nss_ppe_reg_read(PPE_PKT_CODE_RD_OFFSET, &drop_0);

	nss_ppe_reg_write(PPE_PKT_CODE_WR_OFFSET, PPE_PKT_CODE_DROP1_OFFSET);
	nss_ppe_reg_read(PPE_PKT_CODE_RD_OFFSET, &drop_1);

	stats[NSS_STATS_PPE_CODE_DROP] = PPE_PKT_CODE_DROP_GET(drop_0, drop_1);

	nss_ppe_reg_write(PPE_PKT_CODE_WR_OFFSET, PPE_PKT_CODE_CPU_OFFSET);
	nss_ppe_reg_read(PPE_PKT_CODE_RD_OFFSET, &cpu_code);

	stats[NSS_STATS_PPE_CODE_CPU] = PPE_PKT_CODE_CPU_GET(cpu_code);

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_port_drop_code_get()
 *	Get ppe per port drop code.
 */
void nss_ppe_port_drop_code_get(uint32_t *stats, uint8_t port_id)
{
	uint8_t i;
	nss_trace("%s(%d) Start\n", __func__, __LINE__);
	if (!stats) {
		nss_warning("No memory to copy ppe code\n");
		return;
	}

	if (port_id > NSS_PPE_NUM_PHY_PORTS_MAX) {
		nss_warning("Port id is out of range\n");
		return;
	}

	if (!nss_ppe_debug_stats.valid) {
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);

	for (i = 0; i < NSS_STATS_PPE_DROP_CODE_MAX; i++) {
		nss_ppe_reg_read(PPE_DROP_CODE_OFFSET(i, port_id), &stats[i]);
	}

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_cpu_code_exception_get()
 *	Get ppe cpu code specific for flow exceptions.
 */
void nss_ppe_cpu_code_exception_get(uint32_t *stats)
{
	uint8_t i;
	nss_trace("%s(%d) Start\n", __func__, __LINE__);
	if (!stats) {
		nss_warning("No memory to copy ppe code\n");
		return;
	}

	if (!nss_ppe_debug_stats.valid) {
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);

	for (i = 0; i < NSS_STATS_PPE_CPU_CODE_EXCEPTION_MAX ; i++) {
		nss_ppe_reg_read(PPE_CPU_CODE_OFFSET(i), &stats[i]);
	}

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_cpu_code_nonexception_get()
 *	Get ppe cpu code specific for flow exceptions.
 */
void nss_ppe_cpu_code_nonexception_get(uint32_t *stats)
{
	uint8_t i;
	nss_trace("%s(%d) Start\n", __func__, __LINE__);
	if (!stats) {
		nss_warning("No memory to copy ppe code\n");
		return;
	}

	if (!nss_ppe_debug_stats.valid) {
		nss_warning("PPE base address not initialized!\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);

	for (i = 0; i < NSS_STATS_PPE_CPU_CODE_NONEXCEPTION_MAX; i++) {
		nss_ppe_reg_read(PPE_CPU_CODE_OFFSET(ppe_cc_nonexception[i]), &stats[i]);
	}

	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_handler()
 *	Handle NSS -> HLOS messages for ppe tunnel
 */
static void nss_ppe_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_ppe_msg *msg = (struct nss_ppe_msg *)ncm;

	nss_trace("nss_ctx: %p ppe msg: %p", nss_ctx, msg);
	BUG_ON(!nss_ppe_verify_ifnum(ncm->interface));

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncm->type >= NSS_PPE_MSG_MAX) {
		nss_warning("%p: received invalid message %d for PPE interface", nss_ctx, ncm->type);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_ppe_msg)) {
		nss_warning("%p: Length of message is greater than required: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return;
	}

	switch (msg->cm.type) {
	case NSS_PPE_MSG_SYNC_STATS:
		/*
		 * session debug stats embeded in session stats msg
		 */
		nss_ppe_stats_sync(nss_ctx, &msg->msg.stats, ncm->interface);
		break;
	}
}

/*
 * nss_ppe_get_context()
 * 	get NSS context instance for ppe
 */
struct nss_ctx_instance *nss_ppe_get_context(void)
{
	return &nss_top_main.nss[nss_top_main.ppe_handler_id];
}
EXPORT_SYMBOL(nss_ppe_get_context);

/*
 * nss_ppe_register_handler()
 *	debugfs stats msg handler received on static ppe interface
 *
 *	TODO: Export API so that others can also read PPE stats.
 */
void nss_ppe_register_handler(void)
{
	struct nss_ctx_instance *nss_ctx = nss_ppe_get_context();

	nss_core_register_handler(nss_ctx, NSS_PPE_INTERFACE, nss_ppe_handler, NULL);
}

/*
 * nss_ppe_free()
 *	Uninitialize PPE base
 */
void nss_ppe_free(void)
{
	/*
	 * Check if PPE base is already uninitialized.
	 */
	if (!ppe_pvt.ppe_base) {
		return;
	}

	/*
	 * Unmap PPE base address
	 */
	iounmap(ppe_pvt.ppe_base);
	ppe_pvt.ppe_base = NULL;

	spin_lock_bh(&nss_ppe_stats_lock);
	nss_ppe_debug_stats.valid = false;
	nss_ppe_debug_stats.if_num = 0;
	nss_ppe_debug_stats.if_index = 0;
	spin_unlock_bh(&nss_ppe_stats_lock);
}

/*
 * nss_ppe_init()
 *	Initialize PPE base
 */
void nss_ppe_init(void)
{
	/*
	 * Check if PPE base is already initialized.
	 */
	if (ppe_pvt.ppe_base) {
		return;
	}

	/*
	 * Get the PPE base address
	 */
	ppe_pvt.ppe_base = ioremap_nocache(PPE_BASE_ADDR, PPE_REG_SIZE);
	if (!ppe_pvt.ppe_base) {
		nss_warning("DRV can't get PPE base address\n");
		return;
	}

	spin_lock_bh(&nss_ppe_stats_lock);
	nss_ppe_debug_stats.valid = true;
	nss_ppe_debug_stats.if_num = 0;
	nss_ppe_debug_stats.if_index = 0;
	spin_unlock_bh(&nss_ppe_stats_lock);
}

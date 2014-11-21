/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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

/* nss_ipsecmgr.c
 *	NSS to HLOS IPSec Manager
 */
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <asm/atomic.h>
#include <nss_api_if.h>
#include <nss_ipsec.h>
#include "nss_ipsecmgr.h"

#if defined(CONFIG_DYNAMIC_DEBUG)
/*
 * Compile messages for dynamic enable/disable
 */
#define nss_ipsecmgr_error(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define nss_ipsecmgr_warn(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define nss_ipsecmgr_info(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define nss_ipsecmgr_trace(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#else
/*
 * Statically compile messages at different levels
 */
#define nss_ipsecmgr_error(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL < NSS_IPSECMGR_DEBUG_LVL_ERROR) {	\
		pr_alert("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	}	\
}
#define nss_ipsecmgr_warn(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL < NSS_IPSECMGR_DEBUG_LVL_WARN) {	\
		pr_warn("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	}	\
}
#define nss_ipsecmgr_info(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL < NSS_IPSECMGR_DEBUG_LVL_INFO) {	\
		pr_notice("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	}	\
}
#define nss_ipsecmgr_trace(s, ...) {	\
	if (NSS_IPSECMGR_DEBUG_LEVEL < NSS_IPSECMGR_DEBUG_LVL_TRACE) {	\
		pr_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	}	\
}

#endif /* !CONFIG_DYNAMIC_DEBUG */

/* NSS IPsec entry state */
enum nss_ipsecmgr_entry_state {
	NSS_IPSECMGR_ENTRY_STATE_INIT = 0,		/* init state of the entry */
	NSS_IPSECMGR_ENTRY_STATE_VALID = 1,		/* entry is valid */
	NSS_IPSECMGR_ENTRY_STATE_INVALID = 2,		/* entry is invalid */
	NSS_IPSECMGR_ENTRY_STATE_MAX
};

/* IPsec table entry */
struct nss_ipsecmgr_tbl_entry {
	struct nss_ipsec_rule_sel sel;		/* rule selector */
	struct nss_ipsec_sa_stats stats;	/* per entry stats */
	enum nss_ipsecmgr_entry_state state;	/* state */
};

/* NSS IPsec table type */
struct nss_ipsecmgr_tbl {
	uint32_t total_tx;					/* total packets tx'ed from ENCAP/DECAP */
	uint32_t total_rx;					/* total packets rx'ed at ENCAP/DECAP */
	uint32_t total_dropped;					/* total dropped packets at ENCAP/DECAP */
	struct nss_ipsecmgr_tbl_entry entry[NSS_IPSEC_MAX_SA];	/* table entry */
	uint32_t count;						/* number of entries */
	spinlock_t lock;
};

/* NSS IPsec manager private structure */
struct nss_ipsecmgr_priv {
	struct nss_ipsecmgr_tbl encap;		/* encap table */
	struct nss_ipsecmgr_tbl decap;		/* decap table */

	void *cb_ctx;				/* callback context */
	nss_ipsecmgr_callback_t cb_fn;		/* callback function */
	struct nss_ctx_instance *nss_ctx;	/* NSS context */
};

typedef bool (*nss_ipsecmgr_op_t)(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim);

/* NSS IPsec manager operation (message types) complete routines */
struct nss_ipsecmgr_ops {
	nss_ipsecmgr_op_t verify_fn;	/* verify function for the op */
	nss_ipsecmgr_op_t commit_fn;	/* commit function for the op */
};

/* driver global info */
struct nss_ipsecmgr_drv {
	atomic_t sa_count;	/* number of SA's available for */
};

/*
 **********************
 * globals
 **********************
 */

static struct nss_ipsecmgr_drv gbl_drv_ctx;	/* global driver context */

/*
 **********************
 * Helper Functions
 **********************
 */

/*
 * nss_ipsecmgr_get_tbl()
 * 	return the table associated with the interface number
 */
static inline struct nss_ipsecmgr_tbl *nss_ipsecmgr_get_tbl(struct nss_ipsecmgr_priv *priv, uint16_t if_num)
{
	switch (if_num) {
	case NSS_IPSEC_ENCAP_IF_NUMBER:
		return &priv->encap;

	case NSS_IPSEC_DECAP_IF_NUMBER:
		return &priv->decap;

	default:
		return NULL;
	}
}

/*
 * nss_ipsecmgr_copy_encap_add()
 * 	prepare the IPsec message for encap add operation
 */
static void nss_ipsecmgr_copy_encap_add(struct net_device *dev, struct nss_ipsec_rule *msg, union nss_ipsecmgr_rule *rule)
{
	struct nss_ipsecmgr_encap_add *encap = &rule->encap_add;
	struct nss_ipsec_rule_sel *sel = &msg->sel;
	struct nss_ipsec_rule_oip *oip = &msg->oip;
	struct nss_ipsec_rule_data *data = &msg->data;

	/*
	 * Populate the selectors for encap direction
	 */
	sel->ipv4_src = encap->inner_ipv4_src;
	sel->ipv4_dst = encap->inner_ipv4_dst;

	sel->src_port = encap->inner_src_port;
	sel->dst_port = encap->inner_dst_port;

	sel->ipv4_proto = encap->inner_ipv4_proto;

	/*
	 * Populate the outer IP data for encap direction
	 */
	oip->ipv4_dst = encap->outer_ipv4_dst;
	oip->ipv4_src = encap->outer_ipv4_src;

	oip->esp_spi = encap->esp_spi;

	oip->ipv4_ttl = encap->outer_ipv4_ttl;

	/*
	 * Populate the data part
	 */
	data->cipher_algo = encap->cipher_algo;
	data->esp_seq_skip = (encap->esp_seq_skip == 1);
	data->esp_tail_skip = (encap->esp_tail_skip == 1);

	data->esp_icv_len = encap->esp_icv_len;
	data->auth_algo = encap->auth_algo;

	data->crypto_index = encap->crypto_index;

	data->nat_t_req = encap->nat_t_req;
	data->use_pattern = encap->use_pattern;
}

/*
 * nss_ipsecmgr_copy_decap_add()
 * 	prepare the IPsec message for decap add operation
 */
static void nss_ipsecmgr_copy_decap_add(struct net_device *dev, struct nss_ipsec_rule *msg, union nss_ipsecmgr_rule *rule)
{
	struct nss_ipsecmgr_decap_add *decap = &rule->decap_add;
	struct nss_ipsec_rule_sel *sel = &msg->sel;
	struct nss_ipsec_rule_data *data = &msg->data;
	/*
	 * Populate the selectors for encap direction
	 */
	sel->ipv4_src = decap->outer_ipv4_src;
	sel->ipv4_dst = decap->outer_ipv4_dst;

	sel->esp_spi = decap->esp_spi;

	sel->ipv4_proto = IPPROTO_ESP;

	/*
	 * Populate the data part
	 */
	data->cipher_algo = decap->cipher_algo;

	data->esp_icv_len = decap->esp_icv_len;
	data->esp_seq_skip = (decap->esp_seq_skip == 1);
	data->esp_tail_skip = (decap->esp_tail_skip == 1);
	data->auth_algo = decap->auth_algo;

	data->crypto_index = decap->crypto_index;

	data->nat_t_req = decap->nat_t_req;
	if (data->nat_t_req) {
		sel->dst_port = NSS_IPSECMGR_NATT_PORT_DATA;
	}

	data->window_size = decap->window_size;
}

/*
 * nss_ipsecmgr_copy_encap_del()
 * 	prepare the IPsec message for encap del operation
 */
static void nss_ipsecmgr_copy_encap_del(struct net_device *dev, struct nss_ipsec_rule *msg, union nss_ipsecmgr_rule *rule)
{
	struct nss_ipsecmgr_encap_del *encap = &rule->encap_del;
	struct nss_ipsec_rule_sel *sel = &msg->sel;

	/*
	 * Populate the selectors for encap direction
	 */
	sel->ipv4_src = encap->inner_ipv4_src;
	sel->ipv4_dst = encap->inner_ipv4_dst;

	sel->src_port = encap->inner_src_port;
	sel->dst_port = encap->inner_dst_port;

	sel->ipv4_proto = encap->inner_ipv4_proto;
}

/*
 * nss_ipsecmgr_copy_decap_del()
 * 	prepare the IPsec message for decap del operation
 */
static void nss_ipsecmgr_copy_decap_del(struct net_device *dev, struct nss_ipsec_rule *msg, union nss_ipsecmgr_rule *rule)
{
	struct nss_ipsecmgr_decap_del *decap = &rule->decap_del;
	struct nss_ipsec_rule_sel *sel = &msg->sel;
	/*
	 * Populate the selectors for encap direction
	 */
	sel->ipv4_src = decap->outer_ipv4_src;
	sel->ipv4_dst = decap->outer_ipv4_dst;

	sel->esp_spi = decap->esp_spi;

	sel->ipv4_proto = IPPROTO_ESP;
}

/*
 **********************
 * message handlers
 **********************
 */
/*
 * nss_ipsecmgr_verify_add()
 * 	verify the Add operation before committing
 */
static bool nss_ipsecmgr_verify_add(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_rule *rule = &nim->msg.push;
	struct nss_ipsecmgr_tbl_entry *entry;
	uint32_t tbl_idx;

	tbl_idx = rule->index;
	if (tbl_idx >= NSS_IPSEC_MAX_SA) {
		nss_ipsecmgr_error("table index out of range\n");
		return false;
	}

	entry = &tbl->entry[tbl_idx];

	/*
	 * XXX:Duplicate hit or hash collision; We need to handle
	 * hash collision
	 */
	if (entry->state == NSS_IPSECMGR_ENTRY_STATE_VALID) {
		return false;
	}

	/*
	 * Table full, XXX:must increment stats
	 */
	if ((tbl->count + 1) >= NSS_IPSEC_MAX_SA) {
		return false;
	}

	return true;
}

/*
 * nss_ipsecmgr_commit_add()
 * 	commit the Add operation
 */
static bool nss_ipsecmgr_commit_add(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_rule *rule = &nim->msg.push;
	struct nss_ipsecmgr_tbl_entry *entry;
	uint32_t tbl_idx;

	/* Reduce the number of availabe SA(s) as we have successfully added one */
	atomic_dec(&gbl_drv_ctx.sa_count);

	tbl_idx = rule->index;
	entry = &tbl->entry[tbl_idx];

	tbl->count++;

	memcpy(&entry->sel, &rule->sel, sizeof(struct nss_ipsec_rule_sel));
	entry->state = NSS_IPSECMGR_ENTRY_STATE_VALID;

	return true;
}

/*
 * nss_ipsecmgr_verify_del()
 * 	verify the del operation before committing
 */
static bool nss_ipsecmgr_verify_del(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_rule *rule = &nim->msg.push;
	struct nss_ipsecmgr_tbl_entry *entry;
	uint32_t tbl_idx;

	tbl_idx = rule->index;
	if (tbl_idx >= NSS_IPSEC_MAX_SA) {
		nss_ipsecmgr_error("table index out of range\n");
		return false;
	}

	entry = &tbl->entry[tbl_idx];

	/*
	 * Entry already deleted, XXX:must increment stats
	 */
	if (entry->state == NSS_IPSECMGR_ENTRY_STATE_INVALID) {
		return false;
	}

	/*
	 * Entry never existed, XXX:must increment stats
	 */
	if (entry->state == NSS_IPSECMGR_ENTRY_STATE_INIT) {
		return false;
	}

	/*
	 * Table empty, XXX:must increment stats
	 */
	if (tbl->count == 0) {
		return false;
	}

	return true;
}

/*
 * nss_ipsecmgr_commit_del()
 * 	commit the Del operation
 */
static bool nss_ipsecmgr_commit_del(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_rule *rule = &nim->msg.push;
	struct nss_ipsecmgr_tbl_entry *entry;
	uint32_t tbl_idx;

	/* Increase the number of available SA(s) as we have successfully freed one */
	atomic_inc(&gbl_drv_ctx.sa_count);

	tbl_idx = rule->index;
	entry = &tbl->entry[tbl_idx];

	tbl->count--;

	memset(&entry->sel, 0, sizeof(struct nss_ipsec_rule_sel));
	entry->state = NSS_IPSECMGR_ENTRY_STATE_INVALID;

	return true;
}

/*
 * nss_ipsecmgr_verify_stats()
 * 	verify stats update operation
 */
static bool nss_ipsecmgr_verify_stats(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_stats *stats = &nim->msg.stats;

	/*
	 * Table empty, nothing to update
	 */
	if (tbl->count == 0) {
		return false;
	}

	/*
	 * nothing to update
	 */
	if (stats->num_entries == 0) {
		return false;
	}

	return true;
}

/*
 * nss_ipsecmgr_commit_stats()
 * 	commit stats for the SA
 */
static bool nss_ipsecmgr_commit_stats(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	struct nss_ipsec_stats *stats = &nim->msg.stats;
	struct nss_ipsec_sa_stats *sa_stats;
	struct nss_ipsecmgr_tbl_entry *entry;
	uint32_t tbl_idx;
	int i;

	tbl->total_tx = stats->total_tx;
	tbl->total_rx = stats->total_rx;
	tbl->total_dropped = stats->total_dropped;

	for (i = 0; i < stats->num_entries; i++) {
		sa_stats = &stats->sa[i];
		tbl_idx = sa_stats->index;

		entry = &tbl->entry[tbl_idx];

		memcpy(&entry->stats, sa_stats, sizeof(struct nss_ipsec_sa_stats));
	}

	return true;
}

/*
 * nss_ipsecmgr_verify_flush()
 * 	verify the flush operation
 */
static bool nss_ipsecmgr_verify_flush(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	return true;
}

/*
 * nss_ipsecmgr_commit_flush()
 * 	commit the flush operation
 */
static bool nss_ipsecmgr_commit_flush(struct net_device *dev, struct nss_ipsecmgr_tbl *tbl, struct nss_ipsec_msg *nim)
{
	tbl->count = 0;

	return true;
}

/*
 * callback operation
 */
const static struct nss_ipsecmgr_ops cb_ops[NSS_IPSEC_MSG_TYPE_MAX] = {
	[NSS_IPSEC_MSG_TYPE_ADD_RULE] = {nss_ipsecmgr_verify_add, nss_ipsecmgr_commit_add},
	[NSS_IPSEC_MSG_TYPE_DEL_RULE] = {nss_ipsecmgr_verify_del, nss_ipsecmgr_commit_del},
	[NSS_IPSEC_MSG_TYPE_SYNC_STATS] = {nss_ipsecmgr_verify_stats, nss_ipsecmgr_commit_stats},
	[NSS_IPSEC_MSG_TYPE_FLUSH_TUN] = {nss_ipsecmgr_verify_flush, nss_ipsecmgr_commit_flush}
};

/*
 * nss_ipsecmgr_op_receive()
 * 	asynchronous event reception
 */
static void nss_ipsecmgr_op_receive(void *app_data, struct nss_ipsec_msg *nim)
{
	struct net_device *tun_dev = (struct net_device *)app_data;
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsecmgr_tbl *tbl;
	nss_ipsecmgr_op_t verify_fn;
	nss_ipsecmgr_op_t commit_fn;
	struct net_device *dev;

	BUG_ON(tun_dev == NULL);
	BUG_ON(nim == NULL);

	/* this holds the ref_cnt for the device */
	dev = dev_get_by_index(&init_net, nim->tunnel_id);
	if (dev == NULL) {
		nss_ipsecmgr_error("event received on deallocated I/F (%d)\n", nim->tunnel_id);
		return;
	}

	if (dev != tun_dev) {
		nss_ipsecmgr_error("event received on incorrect I/F (%d)\n", nim->tunnel_id);
		goto done;
	}

	priv = netdev_priv(dev);

	tbl = nss_ipsecmgr_get_tbl(priv, nim->cm.interface);
	if (tbl == NULL) {
		nss_ipsecmgr_error("invalid interface number(%d)\n", nim->cm.interface);
		goto done;
	}

	verify_fn = cb_ops[nim->cm.type].verify_fn;
	commit_fn = cb_ops[nim->cm.type].commit_fn;

	if (!verify_fn || !commit_fn) {
		nss_ipsecmgr_error("unhandled type (%d)\n", nim->cm.type);
		goto done;
	}

	/*
	 * Now we can operate on the entry of the table
	 */
	spin_lock_bh(&tbl->lock);

	if (verify_fn(dev, tbl, nim) == true) {
		commit_fn(dev, tbl, nim);
	}

	spin_unlock_bh(&tbl->lock);
done:
	/* release the device as we are done */
	dev_put(dev);
}

/*
 * nss_ipsecmgr_op_send()
 * 	Push a IPsec rule to NSS
 */
static bool nss_ipsecmgr_op_send(struct net_device *dev, struct nss_ipsec_msg *nim, uint32_t if_num, enum nss_ipsec_msg_type type)
{
	struct nss_ipsecmgr_priv *priv;
	nss_tx_status_t status;

	priv = netdev_priv(dev);
	if (priv->nss_ctx == NULL) {
		nss_ipsecmgr_error("Tunnel registration or de-registration is underway\n");
		return false;
	}

	nim->tunnel_id = dev->ifindex;

	nss_ipsec_msg_init(nim, if_num, type, NSS_IPSEC_MSG_LEN, (nss_ipsec_msg_callback_t *)nss_ipsecmgr_op_receive, dev);

	status = nss_ipsec_tx_msg(priv->nss_ctx, nim);
	if (status != NSS_TX_SUCCESS) {
		nss_ipsecmgr_error("unable to push rule(%d) for %s\n", type, dev->name);
		return false;
	}

	return true;
}

/*
 * nss_ipsecmgr_buf_receive()
 *	receive NSS exception packets
 */
static void nss_ipsecmgr_buf_receive(struct net_device *dev, struct sk_buff *skb, __attribute((unused)) struct napi_struct *napi)
{
	struct nss_ipsecmgr_priv *priv;
	nss_ipsecmgr_callback_t cb_fn;
	void *cb_ctx;
	struct iphdr *ip;

	BUG_ON(dev == NULL);
	BUG_ON(skb == NULL);

	/* hold the device till we process it */
	dev_hold(dev);

	/*
	 * XXX:need to ensure that the dev being accessed is not deleted
	 */
	priv = netdev_priv(dev);

	skb->dev = dev;

	cb_fn = priv->cb_fn;
	cb_ctx = priv->cb_ctx;

	/*
	 * if tunnel creator gave a callback then send the packet without
	 * any modifications to him
	 */
	if (cb_fn && cb_ctx) {
		cb_fn(cb_ctx, skb);
		goto done;
	}

	ip = (struct iphdr *)skb->data;
	if ((ip->version != IPVERSION) || (ip->ihl != 5)) {
		nss_ipsecmgr_error("dropping packets(IP version:%x, Header len:%x)\n", ip->version, ip->ihl);
		dev_kfree_skb_any(skb);
		goto done;
	}

	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = cpu_to_be16(ETH_P_IP);
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);
done:
	/* release the device as we are done */
	dev_put(dev);
}

/*
 **********************
 * Netdev ops
 **********************
 */

/*
 * nss_ipsecmgr_tunnel_init()
 * 	initiallizes the tunnel
 */
static int nss_ipsecmgr_tunnel_init(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	priv->nss_ctx = nss_ipsec_get_context();

	return 0;
}

/*
 * nss_ipsecmgr_tunnel_exit()
 * 	deinitiallizes the tunnel
 */
static void nss_ipsecmgr_tunnel_exit(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	priv->nss_ctx = NULL;
}

/*
 * nss_ipsecmgr_tunnel_open()
 * 	open the tunnel for usage
 */
static int nss_ipsecmgr_tunnel_open(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	netif_start_queue(dev);

	return 0;
}

/*
 * nss_ipsecmgr_tunnel_stop()
 * 	stop the IPsec tunnel
 */
static int nss_ipsecmgr_tunnel_stop(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;

	priv = netdev_priv(dev);

	netif_stop_queue(dev);

	return 0;
}

/*
 * nss_ipsecmgr_tunnel_xmit()
 * 	tunnel transmit function
 */
static netdev_tx_t nss_ipsecmgr_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	uint32_t if_num;
	struct iphdr *inner_ip;
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsecmgr_tbl *encap;

	if_num = NSS_IPSEC_ENCAP_IF_NUMBER;
	priv = netdev_priv(dev);
	encap = &priv->encap;

	if (skb_is_nonlinear(skb)) {
		nss_ipsecmgr_error("%p: NSS IPSEC does not support fragments %p\n", priv->nss_ctx, skb);
		goto fail;
	}

	/*
	 * Check if skb is shared
	 */
	if (unlikely(skb_shared(skb))) {
		nss_ipsecmgr_error("%p: Shared skb is not supported: %p\n", priv->nss_ctx, skb);
		goto fail;
	}

	/*
	 * Check the packet head room & tail room
	 */
	if (unlikely(skb_headroom(skb) < dev->needed_headroom)) {
		nss_ipsecmgr_error("%p: Insufficient head room :%d in skb: %p\n", priv->nss_ctx, skb_headroom(skb), skb);
		goto fail;
	}

	if (unlikely(skb_tailroom(skb) < dev->needed_tailroom)) {
		nss_ipsecmgr_error("%p: Insufficient tail room:%d in skb: %p\n", priv->nss_ctx, skb_tailroom(skb), skb);
		goto fail;
	}

	/*
	 * Check if packet is given starting from network header
	 */
	if (skb->data != skb_network_header(skb)) {
		nss_ipsecmgr_error("%p: 'Skb data is not starting from IP header", priv->nss_ctx);
		goto fail;
	}

	inner_ip = (struct iphdr *)ip_hdr(skb);

	/*
	 * Validate if packet has ip options
	 */
	if ((inner_ip->version != IPVERSION) || (inner_ip->ihl != 5)) {
		nss_ipsecmgr_error("%p: Unsupported IP header ipver: 0x%x iphdr_len: 0x%x\n", priv->nss_ctx,
						inner_ip->version, inner_ip->ihl);
		goto fail;
	}

	/*
	 * Check the TTL value
	 */
	if ((inner_ip->ttl == 0)) {
		nss_ipsecmgr_error("%p: IP TTL is zero, unabled to transmit\n", priv->nss_ctx);
		goto fail;
	}

	/*
	 * Send the packet down
	 */
	if (nss_ipsec_tx_buf(skb, if_num) != 0) {
		/*
		 * TODO: NEED TO STOP THE QUEUE
		 */
		goto fail;
	}

	/*
	 * Increment the tx count
	 */
	encap->total_tx++;

	return NETDEV_TX_OK;

fail:
	return NETDEV_TX_BUSY;
}

/*
 * nss_ipsecmgr_tunnel_stats()
 * 	get tunnel statistics
 */
static struct net_device_stats *nss_ipsecmgr_tunnel_stats(struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsecmgr_tbl *encap;
	struct nss_ipsecmgr_tbl *decap;

	priv = netdev_priv(dev);

	encap = &priv->encap;
	decap = &priv->decap;

	stats->rx_packets = encap->total_rx + decap->total_rx;
	stats->tx_packets = encap->total_tx + decap->total_tx;
	stats->tx_dropped = encap->total_dropped + decap->total_dropped;

	return stats;
}

/* NSS IPsec tunnel operation */
static const struct net_device_ops nss_ipsecmgr_tunnel_ops = {
	.ndo_init = nss_ipsecmgr_tunnel_init,
	.ndo_uninit = nss_ipsecmgr_tunnel_exit,
	.ndo_start_xmit = nss_ipsecmgr_tunnel_xmit,
	.ndo_open = nss_ipsecmgr_tunnel_open,
	.ndo_stop = nss_ipsecmgr_tunnel_stop,
	.ndo_get_stats = nss_ipsecmgr_tunnel_stats,
};

/*
 * nss_ipsecmgr_tunnel_free()
 * 	free an existing IPsec tunnel interface
 */
static void nss_ipsecmgr_tunnel_free(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv = netdev_priv(dev);
	struct nss_ipsecmgr_tbl *encap_tbl;
	struct nss_ipsecmgr_tbl *decap_tbl;

	encap_tbl = &priv->encap;
	decap_tbl = &priv->decap;

	nss_ipsecmgr_info("IPsec tunnel device(%s) freed\n", dev->name);
	nss_ipsecmgr_info("Entries left: encap(%d), decap(%d)\n", encap_tbl->count, decap_tbl->count);

	free_netdev(dev);
}

/*
 * nss_ipsecmr_setup_tunnel()
 * 	setup the IPsec tunnel
 */
static void nss_ipsecmgr_tunnel_setup(struct net_device *dev)
{
	dev->addr_len = ETH_ALEN;
	dev->mtu = NSS_IPSECMGR_TUN_MTU(ETH_DATA_LEN);

	dev->hard_header_len = NSS_IPSECMGR_TUN_MAX_HDR_LEN;
	dev->needed_headroom = NSS_IPSECMGR_TUN_HEADROOM;
	dev->needed_tailroom = NSS_IPSECMGR_TUN_TAILROOM;

	dev->type = NSS_IPSEC_ARPHRD_IPSEC;

	dev->ethtool_ops = NULL;
	dev->header_ops = NULL;
	dev->netdev_ops = &nss_ipsecmgr_tunnel_ops;

	dev->destructor = nss_ipsecmgr_tunnel_free;

	/*
	 * XXX:should get the MAC address from the ethernet device
	 */
	memcpy(dev->dev_addr, "\xaa\xbb\xcc\xdd\xee\xff", dev->addr_len);
	memset(dev->broadcast, 0xff, dev->addr_len);
	memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);
}

/*
 **********************
 * Exported Functions
 **********************
 */

/*
 * nss_ipsecmgr_tunnel_add()
 * 	add a IPsec pseudo tunnel device
 */
struct net_device *nss_ipsecmgr_tunnel_add(void *cb_ctx, nss_ipsecmgr_callback_t cb)
{
	struct net_device *dev;
	struct nss_ipsecmgr_priv *priv;
	int status;
	int32_t if_number;

	dev = alloc_netdev(sizeof(struct nss_ipsecmgr_priv), NSS_IPSECMGR_TUN_NAME, nss_ipsecmgr_tunnel_setup);
	if (!dev) {
		nss_ipsecmgr_error("unable to allocate a tunnel device\n");
		return NULL;
	}

	priv = netdev_priv(dev);

	priv->cb_ctx = cb_ctx;
	priv->cb_fn = cb;

	spin_lock_init(&priv->encap.lock);
	spin_lock_init(&priv->decap.lock);

	status = rtnl_is_locked() ? register_netdevice(dev) : register_netdev(dev);
	if (status < 0) {
		goto fail;
	}

	if_number = nss_ipsec_get_interface(priv->nss_ctx);
	if (if_number < 0) {
		nss_ipsecmgr_error("Invalid nss interface :%d\n", if_number);
		return NULL;
	}

	nss_ipsec_data_register(if_number, nss_ipsecmgr_buf_receive, dev);

	nss_ipsec_notify_register(NSS_IPSEC_ENCAP_IF_NUMBER, nss_ipsecmgr_op_receive, dev);
	nss_ipsec_notify_register(NSS_IPSEC_DECAP_IF_NUMBER, nss_ipsecmgr_op_receive, dev);

	return dev;

fail:
	free_netdev(dev);

	return NULL;
}
EXPORT_SYMBOL(nss_ipsecmgr_tunnel_add);

/*
 * nss_ipsecmgr_del_tunnel()
 * 	delete an existing IPsec tunnel
 */
bool nss_ipsecmgr_tunnel_del(struct net_device *dev)
{
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsecmgr_tbl *encap;
	struct nss_ipsecmgr_tbl *decap;
	struct nss_ipsec_msg nim;
	bool status;

	priv = netdev_priv(dev);

	encap = &priv->encap;
	decap = &priv->decap;

	/*
	 * Unregister the callbacks from the HLOS as we are no longer
	 * interested in exception data & async messages
	 */

	nss_ipsec_data_unregister(priv->nss_ctx, NSS_C2C_TX_INTERFACE);

	nss_ipsec_notify_unregister(priv->nss_ctx, NSS_IPSEC_ENCAP_IF_NUMBER);
	nss_ipsec_notify_unregister(priv->nss_ctx, NSS_IPSEC_DECAP_IF_NUMBER);

	nss_ipsec_data_unregister(priv->nss_ctx, NSS_IPSEC_DECAP_IF_NUMBER);
	nss_ipsec_data_unregister(priv->nss_ctx, NSS_IPSEC_ENCAP_IF_NUMBER);

	priv->cb_fn = NULL;
	priv->cb_ctx = NULL;

	/*
	 * Prepare to flush all SA(s) inside a tunnel
	 */
	memset(&nim, 0, sizeof(struct nss_ipsec_msg));

	status = nss_ipsecmgr_op_send(dev, &nim, NSS_IPSEC_ENCAP_IF_NUMBER, NSS_IPSEC_MSG_TYPE_FLUSH_TUN);
	if (status != true) {
		nss_ipsecmgr_error("unable complete tunnel deletion, for ingress rules\n");
		goto fail;
	}

	/* release all SA(s) associated with the encap */
	atomic_sub(encap->count, &gbl_drv_ctx.sa_count);

	status = nss_ipsecmgr_op_send(dev, &nim, NSS_IPSEC_DECAP_IF_NUMBER, NSS_IPSEC_MSG_TYPE_FLUSH_TUN);
	if (status != true) {
		nss_ipsecmgr_error("unable complete tunnel deletion, for egress rules\n");
		goto fail;
	}

	/* release all SA(s) associated with the decap */
	atomic_sub(decap->count, &gbl_drv_ctx.sa_count);

	/*
	 * The unregister should start here but the expectation is that the free would
	 * happen when the reference count goes down to '0'
	 */
	rtnl_is_locked() ? unregister_netdevice(dev) : unregister_netdev(dev);

	return true;
fail:
	/* caller must retry */
	return false;
}
EXPORT_SYMBOL(nss_ipsecmgr_tunnel_del);

/*
 * nss_ipsecmgr_sa_add()
 * 	add a new SA to the tunnel
 */
bool nss_ipsecmgr_sa_add(struct net_device *dev, union nss_ipsecmgr_rule *rule, enum nss_ipsecmgr_rule_type type)
{
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsec_msg nim;
	uint32_t if_num;

	priv = netdev_priv(dev);

	/* check if there are free SA(s) */
	if (atomic_read(&gbl_drv_ctx.sa_count) == 0) {
		return false;
	}

	memset(&nim, 0, sizeof(struct nss_ipsec_msg));

	/* XXX: some basic validation of the passed rule needs to happen */

	switch (type) {
	case NSS_IPSECMGR_RULE_TYPE_ENCAP:
		if_num = NSS_IPSEC_ENCAP_IF_NUMBER;
		nss_ipsecmgr_copy_encap_add(dev, &nim.msg.push, rule);
		break;

	case NSS_IPSECMGR_RULE_TYPE_DECAP:
		if_num = NSS_IPSEC_DECAP_IF_NUMBER;
		nss_ipsecmgr_copy_decap_add(dev, &nim.msg.push, rule);
		break;

	default:
		nss_ipsecmgr_error("Unknown rule type(%d) for Add operation\n", type);
		return false;
	}

	return nss_ipsecmgr_op_send(dev, &nim, if_num, NSS_IPSEC_MSG_TYPE_ADD_RULE);

}
EXPORT_SYMBOL(nss_ipsecmgr_sa_add);

/*
 * nss_ipsecmgr_sa_del()
 *
 */
bool nss_ipsecmgr_sa_del(struct net_device *dev, union nss_ipsecmgr_rule *rule, enum nss_ipsecmgr_rule_type type)
{
	struct nss_ipsecmgr_priv *priv;
	struct nss_ipsec_msg nim;
	uint32_t if_num;

	priv = netdev_priv(dev);

	/* check if all SA(s) are already freed */
	if (atomic_read(&gbl_drv_ctx.sa_count) == NSS_IPSEC_MAX_SA) {
		return false;
	}

	memset(&nim, 0, sizeof(struct nss_ipsec_msg));

	/* XXX: some basic validation of the passed rule needs to happen */

	switch (type) {
	case NSS_IPSECMGR_RULE_TYPE_ENCAP:
		if_num = NSS_IPSEC_ENCAP_IF_NUMBER;
		nss_ipsecmgr_copy_encap_del(dev, &nim.msg.push, rule);
		break;

	case NSS_IPSECMGR_RULE_TYPE_DECAP:
		if_num = NSS_IPSEC_DECAP_IF_NUMBER;
		nss_ipsecmgr_copy_decap_del(dev, &nim.msg.push, rule);
		break;

	default:
		nss_ipsecmgr_error("Unknown rule type(%d) for Del operation\n", type);
		return false;
	}
	return nss_ipsecmgr_op_send(dev, &nim, if_num, NSS_IPSEC_MSG_TYPE_DEL_RULE);
}
EXPORT_SYMBOL(nss_ipsecmgr_sa_del);

static int __init nss_ipsecmgr_init(void)
{
	nss_ipsecmgr_info("NSS IPsec manager loaded: Build date %s\n", __DATE__);

	memset(&gbl_drv_ctx, 0, sizeof(struct nss_ipsecmgr_drv));

	atomic_set(&gbl_drv_ctx.sa_count, NSS_IPSEC_MAX_SA);

	return 0;
}


static void __exit nss_ipsecmgr_exit(void)
{
	nss_ipsecmgr_info("NSS IPsec manager unloader\n");
}

module_init(nss_ipsecmgr_init);
module_exit(nss_ipsecmgr_exit);

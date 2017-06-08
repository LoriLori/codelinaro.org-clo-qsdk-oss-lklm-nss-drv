/*
 **************************************************************************
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
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
 * nss_dscp2pri.c
 *	NSS dscp2pri node APIs
 */

#include "nss_tx_rx_common.h"

#define NSS_DSCP2PRI_PARAM_FIELD_COUNT 3
#define NSS_DSCP2PRI_ARRAY_SIZE 64

/*
 * dscp2pri mapping structure.
 */
struct nss_dscp2pri_map {
	uint8_t action;		/* Action associated with the DSCP value.*/
	uint8_t priority;	/* Priority associated with the DSCP value. */
};

struct nss_dscp2pri_map mapping[NSS_DSCP2PRI_ARRAY_SIZE];

/*
 * Private data structure
 */
static struct nss_dscp2pri_pvt {
	struct semaphore sem;
	struct completion complete;
	int response;
	void *cb;
	void *app_data;
} dscp2pri_pvt;

/*
 * nss_dscp2pri_usage()
 *	Help function shows the usage of the command.
 */
static void nss_dscp2pri_usage(void)
{
	nss_info_always("\nUsage:\n");
	nss_info_always("echo <dscp> <action> <prio> > /proc/sys/dev/nss/dscp2pri/map\n\n");
	nss_info_always("dscp[0-63] action[0-1] prio[0-3]:\n\n");
}

/*
 * nss_dscp2pri_msg_init()
 *	Initialize dscp2pri message.
 */
static void nss_dscp2pri_msg_init(struct nss_dscp2pri_msg *ndm, uint16_t if_num, uint32_t type,
		      uint32_t len, nss_dscp2pri_msg_callback_t cb, void *app_data)
{
	nss_cmn_msg_init(&ndm->cm, if_num, type, len, (void *)cb, app_data);
}

/*
 * nss_dscp2pri_tx_msg()
 *	TX message function.
 */
static nss_tx_status_t nss_dscp2pri_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_dscp2pri_msg *ndm)
{
	struct nss_dscp2pri_msg *ndm2;
	struct nss_cmn_msg *ncm = &ndm->cm;
	struct sk_buff *nbuf;
	nss_tx_status_t status;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the message
	 */
	if (ncm->interface != NSS_DSCP2PRI_INTERFACE) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, ncm->interface);
		return NSS_TX_FAILURE;
	}

	if (ncm->type >= NSS_DSCP2PRI_METADATA_TYPE_MAX) {
		nss_warning("%p: message type out of range: %d", nss_ctx, ncm->type);
		return NSS_TX_FAILURE;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_dscp2pri_msg)) {
		nss_warning("%p: tx request for another interface: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return NSS_TX_FAILURE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the message to our skb.
	 */
	ndm2 = (struct nss_dscp2pri_msg *)skb_put(nbuf, sizeof(struct nss_dscp2pri_msg));
	memcpy(ndm2, ndm, sizeof(struct nss_dscp2pri_msg));
	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: unable to send dscp2pri message\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx, NSS_H2N_INTR_DATA_COMMAND_QUEUE);
	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_dscp2pri_configure_mapping_callback_async()
 *	Callback function for async messages.
 */
static void nss_dscp2pri_configure_mapping_callback_async(void *app_data, struct nss_dscp2pri_msg *ndm)
{
	if (ndm->cm.response != NSS_CMN_RESPONSE_ACK) {
		nss_warning("%p: nss dscp2pri configure mapping tx async failed: %d\n",
			    &dscp2pri_pvt, ndm->cm.error);
		return;
	}

	nss_info("%p: nss dscp2pri configure mapping tx async succeeded\n", &dscp2pri_pvt);

	/*
	 * NSS firmware acknowleged the configuration, so update the mapping table on HOST side as well.
	 * Note that action value was sent to NSS firmware as opaque, because action is not needed in
	 * NSS firmware. It is only used in HOST code.
	 */
	mapping[ndm->msg.configure_mapping.dscp].action = ndm->msg.configure_mapping.opaque;
	mapping[ndm->msg.configure_mapping.dscp].priority = ndm->msg.configure_mapping.priority;
}

/*
 * nss_dscp2pri_configure_mapping_callback_sync()
 *	Callback function for sync messages.
 */
static void nss_dscp2pri_configure_mapping_callback_sync(void *app_data, struct nss_dscp2pri_msg *ndm)
{
	nss_dscp2pri_msg_callback_t callback = (nss_dscp2pri_msg_callback_t)dscp2pri_pvt.cb;
	void *data = (void *)dscp2pri_pvt.app_data;

	dscp2pri_pvt.cb = NULL;
	dscp2pri_pvt.app_data = NULL;

	if (ndm->cm.response != NSS_CMN_RESPONSE_ACK) {
		dscp2pri_pvt.response = NSS_FAILURE;
		complete(&dscp2pri_pvt.complete);
		nss_warning("%p: nss dscp2pri configure mapping tx sync failed: %d\n",
			    &dscp2pri_pvt, ndm->cm.error);
		return;
	}

	nss_info("%p: nss dscp2pri configure mapping tx sync succeeded\n",
		 &dscp2pri_pvt);

	dscp2pri_pvt.response = NSS_SUCCESS;

	if (callback) {
		callback(data, ndm);
	}

	complete(&dscp2pri_pvt.complete);
}

/*
 * nss_dscp2pri_configure_mapping_async()
 *	Async implementation for sending message to NSS.
 */
static nss_tx_status_t nss_dscp2pri_configure_mapping_async(struct nss_dscp2pri_msg *ndm)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx = &nss_top->nss[0];

	nss_tx_status_t status = nss_dscp2pri_tx_msg(nss_ctx, ndm);
	if (status != NSS_TX_SUCCESS) {
		nss_warning("nss_dscp2pri tx error to send configure mapping message\n");
		return status;
	}

	return NSS_TX_SUCCESS;
}

/*
 * nss_dscp2pri_configure_mapping_sync()
 *	Sync implementation for sending message to NSS.
 */
static nss_tx_status_t nss_dscp2pri_configure_mapping_sync(struct nss_dscp2pri_msg *ndm)
{
	nss_tx_status_t status;
	int ret;

	down(&dscp2pri_pvt.sem);
	dscp2pri_pvt.response = NSS_FAILURE;

	dscp2pri_pvt.cb = (void *)ndm->cm.cb;
	dscp2pri_pvt.app_data = (void *)ndm->cm.app_data;

	ndm->cm.cb = (nss_ptr_t)nss_dscp2pri_configure_mapping_callback_sync;
	ndm->cm.app_data = (nss_ptr_t)ndm;

	status = nss_dscp2pri_configure_mapping_async(ndm);
	if (status != NSS_TX_SUCCESS) {
		goto failure;
	}

	/*
	 * Blocking call, wait till we get ACK for this msg.
	 */
	ret = wait_for_completion_timeout(&dscp2pri_pvt.complete,
			msecs_to_jiffies(NSS_CONN_CFG_TIMEOUT));
	if (!ret) {
		nss_warning("Waiting for ack time out for configure mapping message\n");
		goto failure;
	}

	up(&dscp2pri_pvt.sem);
	return dscp2pri_pvt.response;

failure:
	dscp2pri_pvt.response = NSS_TX_FAILURE;
	up(&dscp2pri_pvt.sem);
	return NSS_TX_FAILURE;
}

/*
 * nss_dscp2pri_sysctl_map_handler()
 *	Sysctl handler for dscp/pri mappings.
 */
static int nss_dscp2pri_sysctl_map_handler(struct ctl_table *ctl, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int count;
	size_t cp_bytes = 0;
	char w_buf[7];
	loff_t w_offset = 0;
	char *str;
	char *tokens[NSS_DSCP2PRI_PARAM_FIELD_COUNT];
	unsigned int dscp, priority, action;
	struct nss_dscp2pri_configure_mapping *cfg;
	struct nss_dscp2pri_msg ndm;
	nss_tx_status_t status;
	int ret;

	/*
	 * It's a read operation
	 */
	if (!write) {
		/*
		 * (64 * 8) + 22 bytes for the buffer size is sufficient to write
		 * the table including the spaces and new line characters.
		 */
		char r_buf[(NSS_DSCP2PRI_ARRAY_SIZE * 8) + 22] = {0};
		int i, len;

		/*
		 * Write the priority values to the first line of the output.
		 */
		len = scnprintf(r_buf + cp_bytes, 11, "%s:  ", "priority");
		cp_bytes += len;
		for (i = 0; i < NSS_DSCP2PRI_ARRAY_SIZE; i++) {
			len = scnprintf(r_buf + cp_bytes, 4, "%d ", mapping[i].priority);
			if (!len) {
				nss_warning("failed to read from buffer %d\n", mapping[i].priority);
				return -EFAULT;
			}
			cp_bytes += len;
		}

		/*
		 * Add new line character at the end.
		 */
		len = scnprintf(r_buf + cp_bytes, 4, "\n");
		cp_bytes += len;

		/*
		 * Write the action values to the second line of the output.
		 */
		len = scnprintf(r_buf + cp_bytes, 11, "%s:    ", "action");
		cp_bytes += len;
		for (i = 0; i < NSS_DSCP2PRI_ARRAY_SIZE; i++) {
			len = scnprintf(r_buf + cp_bytes, 4, "%d ", mapping[i].action);
			if (!len) {
				nss_warning("failed to read from buffer %d\n", mapping[i].action);
				return -EFAULT;
			}
			cp_bytes += len;
		}

		/*
		 * Add new line character at the end.
		 */
		len = scnprintf(r_buf + cp_bytes, 4, "\n");
		cp_bytes += len;

		cp_bytes = simple_read_from_buffer(buffer, *lenp, ppos, r_buf, cp_bytes);
		*lenp = cp_bytes;
		return 0;
	}

	/*
	 * Buffer length cannot be more than 7 and less than 6.
	 */
	if (*lenp < 6 || *lenp > 7) {
		nss_warning("Buffer is not correct. Invalid lenght: %d\n", (int)*lenp);
		nss_dscp2pri_usage();
		return 0;
	}

	/*
	 * It's a write operation
	 */
	cp_bytes = simple_write_to_buffer(w_buf, *lenp, &w_offset, buffer, 7);
	if (cp_bytes != *lenp) {
		nss_warning("failed to write to buffer\n");
		return -EFAULT;
	}

	count = 0;
	str = w_buf;
	tokens[count] = strsep(&str, " ");
	while (tokens[count] != NULL) {
		count++;
		if (count == NSS_DSCP2PRI_PARAM_FIELD_COUNT) {
			nss_warning("maximum allowed field count is %d\n", NSS_DSCP2PRI_PARAM_FIELD_COUNT);
			break;
		}
		tokens[count] = strsep(&str, " ");
	}

	/*
	 * Did we read enough number of parameters from the command line.
	 * There must be 2 parameters.
	 */
	if (count != NSS_DSCP2PRI_PARAM_FIELD_COUNT) {
		nss_warning("param fields are less than expected: %d\n", count);
		nss_dscp2pri_usage();
		return 0;
	}

	/*
	 * Write the tokens to integers.
	 */
	ret = sscanf(tokens[0], "%u", &dscp);
	if (ret != 1) {
		nss_warning("failed to write the dscp token to integer\n");
		return -EFAULT;
	}

	ret = sscanf(tokens[1], "%u", &action);
	if (ret != 1) {
		nss_warning("failed to write the action token to integer\n");
		return -EFAULT;
	}

	ret = sscanf(tokens[2], "%u", &priority);
	if (ret != 1) {
		nss_warning("failed to write the priority token to integer\n");
		return -EFAULT;
	}

	/*
	 * dscp value cannot be higher than 63.
	 */
	if (dscp >= NSS_DSCP2PRI_ARRAY_SIZE) {
		nss_warning("invalid dscp value: %d\n", dscp);
		nss_dscp2pri_usage();
		return 0;
	}

	/*
	 * Action can be 0 or 1.
	 * 0: NSS_DSCP2PRI_ACTION_NOT_ACCEL
	 * 1: NSS_DSCP2PRI_ACTION_ACCEL
	 */
	if (action >= NSS_DSCP2PRI_ACTION_MAX) {
		nss_warning("invalid action value: %d\n", action);
		nss_dscp2pri_usage();
		return 0;
	}

	/*
	 * Priority must be less than NSS_DSCP2PRI_PRIORITY_MAX which is 4.
	 */
	if (priority >= NSS_DSCP2PRI_PRIORITY_MAX) {
		nss_warning("invalid priority value: %d\n", priority);
		nss_dscp2pri_usage();
		return 0;
	}

	nss_info("dscp: %d action: %d priority: %d\n", dscp, action, priority);

	/*
	 * Write the dscp, priority and opaque values to the message fields.
	 * Opaque is set to action value and when the message is acknowledged
	 * by NSS firmware it is used to set the action value in the mapping table.
	 */
	cfg = &ndm.msg.configure_mapping;
	cfg->dscp = (uint8_t)dscp;
	cfg->opaque = (uint8_t)action;
	cfg->priority = (uint8_t)priority;

	/*
	 * Initialize message.
	 */
	nss_dscp2pri_msg_init(&ndm, NSS_DSCP2PRI_INTERFACE,
			      NSS_DSCP2PRI_METADATA_TYPE_CONFIGURE_MAPPING,
			      sizeof(struct nss_dscp2pri_configure_mapping),
			      nss_dscp2pri_configure_mapping_callback_async,
			      (void *)&ndm);

	/*
	 * Send the message to the NSS.
	 */
	status = nss_dscp2pri_configure_mapping_sync(&ndm);
	if (status != NSS_TX_SUCCESS) {
		return -EFAULT;
	}

	return 0;
}

/*
 * nss_dscp2pri_configure_handler()
 *	Handles NSS -> HLOS messages for dscp2pri node.
 */
static void nss_dscp2pri_configure_handler(struct nss_ctx_instance *nss_ctx, struct nss_cmn_msg *ncm, __attribute__((unused))void *app_data)
{
	struct nss_dscp2pri_msg *ndm = (struct nss_dscp2pri_msg *)ncm;
	nss_dscp2pri_msg_callback_t cb;

	BUG_ON(ncm->interface != NSS_DSCP2PRI_INTERFACE);

	/*
	 * Is this a valid request/response packet?
	 */
	if (ncm->type >= NSS_DSCP2PRI_METADATA_TYPE_MAX) {
		nss_warning("%p: received invalid message %d for dscp2pri interface", nss_ctx, ncm->type);
		return;
	}

	if (nss_cmn_get_msg_len(ncm) > sizeof(struct nss_dscp2pri_msg)) {
		nss_warning("%p: Length of message is greater than required: %d", nss_ctx, nss_cmn_get_msg_len(ncm));
		return;
	}

	nss_core_log_msg_failures(nss_ctx, ncm);

	/*
	 * Do we have a callback
	 */
	if (!ncm->cb) {
		nss_trace("%p: cb is null for interface %d", nss_ctx, ncm->interface);
		return;
	}

	cb = (nss_dscp2pri_msg_callback_t)ncm->cb;
	cb((void *)ncm->app_data, ndm);
}

static struct ctl_table nss_dscp2pri_table[] = {
	{
		.procname	= "map",
		.data		= &mapping[NSS_DSCP2PRI_ARRAY_SIZE],
		.maxlen		= sizeof(struct nss_dscp2pri_map),
		.mode		= 0644,
		.proc_handler	= &nss_dscp2pri_sysctl_map_handler,
	},

	{ }
};

static struct ctl_table nss_dscp2pri_dir[] = {
	{
		.procname		= "dscp2pri",
		.mode			= 0555,
		.child			= nss_dscp2pri_table,
	},
	{ }
};


static struct ctl_table nss_dscp2pri_root_dir[] = {
	{
		.procname		= "nss",
		.mode			= 0555,
		.child			= nss_dscp2pri_dir,
	},
	{ }
};

static struct ctl_table nss_dscp2pri_root[] = {
	{
		.procname		= "dev",
		.mode			= 0555,
		.child			= nss_dscp2pri_root_dir,
	},
	{ }
};

static struct ctl_table_header *nss_dscp2pri_header;

/*
 * nss_dscp2pri_get_action()
 *	Gets the action value of the dscp.
 */
enum nss_dscp2pri_action nss_dscp2pri_get_action(uint8_t dscp)
{
	return mapping[dscp].action;
}
EXPORT_SYMBOL(nss_dscp2pri_get_action);

/*
 * nss_dscp2pri_register_sysctl()
 */
void nss_dscp2pri_register_sysctl(void)
{
	/*
	 * Register sysctl table.
	 */
	nss_dscp2pri_header = register_sysctl_table(nss_dscp2pri_root);
}

/*
 * nss_dscp2pri_unregister_sysctl()
 *	Unregister sysctl specific to n2h
 */
void nss_dscp2pri_unregister_sysctl(void)
{
	/*
	 * Unregister sysctl table.
	 */
	if (nss_dscp2pri_header) {
		unregister_sysctl_table(nss_dscp2pri_header);
	}
}

/*
 * nss_dscp2pri_register_handler()
 *      Registering handler for receiving notify msg from dscp2pri node on NSS.
 */
void nss_dscp2pri_register_handler(void)
{
	int i;

	/*
	 * Initialize the mapping table with the default values.
	 */
	for (i = 0; i < NSS_DSCP2PRI_ARRAY_SIZE; i++) {
		mapping[i].priority = NSS_DSCP2PRI_PRIORITY_BE;
		mapping[i].action = NSS_DSCP2PRI_ACTION_ACCEL;
	}

	nss_core_register_handler(NSS_DSCP2PRI_INTERFACE, nss_dscp2pri_configure_handler, NULL);

	/*
	 * dscp2pri sema init.
	 */
	sema_init(&dscp2pri_pvt.sem, 1);
	init_completion(&dscp2pri_pvt.complete);
}

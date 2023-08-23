/* iptables module for the Linux ISG Access Control
 *
 * (C) 2009 by Oleg A. Arkhangelsky <sysoleg@yandex.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include "isg_main.h"
#include "build.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oleg A. Arkhangelsky <sysoleg@yandex.ru>");
MODULE_DESCRIPTION("Xtables: Linux ISG Access Control");
MODULE_ALIAS("ipt_ISG");
MODULE_ALIAS("ipt_isg");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#define xt_in(par) ((par)->in)
#define xt_out(par) ((par)->out)
#endif

static inline struct isg_session *isg_find_session(struct isg_net *, struct isg_in_event *);
static int isg_start_session(struct isg_session *);
static void isg_send_sessions_list(struct isg_net *, pid_t, struct isg_in_event *);
static int isg_free_session(struct isg_session *);
static int isg_clear_session(struct isg_net *, struct isg_in_event *);
static int isg_update_session(struct isg_net *, struct isg_in_event *);
static void isg_send_session_count(struct isg_net *, pid_t);
static struct sk_buff *isg_send_event(struct isg_net *, u_int16_t, struct isg_session *,
						pid_t, int, int, struct sk_buff *);
static void isg_send_event_type(struct isg_net *, pid_t, u_int32_t);
static int isg_add_service_desc(struct isg_net *, u_int8_t *, u_int8_t *);
static int isg_apply_service(struct isg_net *, struct isg_in_event *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void isg_session_timeout(unsigned long);
#else
static void isg_session_timeout(struct timer_list *);
#endif
static void isg_sweep_service_desc_tc(struct isg_net *);
static void isg_send_services_list(struct isg_net *, pid_t, struct isg_in_event *);

static unsigned int nr_buckets = 8192;
module_param(nr_buckets, uint, 0400);
MODULE_PARM_DESC(nr_buckets, "Number of buckets to store current sessions list");

unsigned int nehash_key_len = 20;
module_param(nehash_key_len, uint, 0400);
MODULE_PARM_DESC(nehash_key_len, "Network hash key length (in bits)");

static unsigned int tg_permit_action = 0;
module_param(tg_permit_action, uint, 0400);
MODULE_PARM_DESC(tg_permit_action, "Xtables action for permitted traffic (0 - CONTINUE (default), 1 - ACCEPT)");

static unsigned int tg_deny_action = 0;
module_param(tg_deny_action, uint, 0400);
MODULE_PARM_DESC(tg_deny_action, "Xtables action for denied traffic (0 - DROP (default), 1 - CONTINUE)");

/* Don't touch parameters below (unless you know what you're doing) */

static unsigned int session_check_interval = 10;
module_param(session_check_interval, uint, 0400);

static unsigned int pass_outgoing = 0;
module_param(pass_outgoing, uint, 0400);

static bool module_exiting = 0;
static unsigned int jhash_rnd __read_mostly;

#if !defined(DEFINE_SPINLOCK)
#	define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

static DEFINE_MUTEX(event_mutex);
DEFINE_SPINLOCK(isg_lock);

static int isg_net_id;
static inline struct isg_net *isg_pernet(struct net *net) {
	return net_generic(net, isg_net_id);
}

static struct ctl_table_header *isg_sysctl_hdr;
static struct ctl_table empty_ctl_table[1];

struct ctl_path net_ipt_isg_ctl_path[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	{ .procname = "net", .ctl_name = CTL_NET, },
#else
	{ .procname = "net", },
#endif
	{ .procname = "ipt_ISG", },
	{ },
};

static struct ctl_table isg_net_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.ctl_name	= CTL_UNNUMBERED,
#endif
	.procname	= "tg_permit_action",
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= proc_dointvec
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.ctl_name	= CTL_UNNUMBERED,
#endif
	.procname	= "tg_deny_action",
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= proc_dointvec
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.ctl_name	= CTL_UNNUMBERED,
#endif
	.procname	= "pass_outgoing",
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= proc_dointvec
	},
	{ },
};

#ifdef DEBUG
#define isg_log(fmt,...) printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define isg_log(fmt,...) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

static void isg_nl_receive_skb(struct sk_buff *skb) {
	struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;
	struct isg_in_event *ev = (struct isg_in_event *) NLMSG_DATA(nlh);
	pid_t from_pid = nlh->nlmsg_pid;

	struct isg_net *isg_net = isg_pernet(sock_net(skb->sk));

	switch (ev->type & 0xFF) {
		int type;

		case EVENT_LISTENER_REG:
			isg_net->listener_pid = from_pid;
			isg_net->listener_ver = (u8)((ev->type & 0xFF00) >> 8);
			printk(KERN_INFO "ipt_ISG: Listener daemon with pid %d registered\n", from_pid);
			break;

		case EVENT_SESS_APPROVE:
		case EVENT_SESS_CHANGE:
			if (isg_update_session(isg_net, ev)) {
				type = EVENT_KERNEL_NACK;
			} else {
				type = EVENT_KERNEL_ACK;
			}
			if (ev->type == EVENT_SESS_CHANGE) {
				isg_send_event_type(isg_net, from_pid, type);
			}
			break;

		case EVENT_SERV_APPLY:
			isg_apply_service(isg_net, ev);
			break;

		case EVENT_SESS_GETLIST:
			isg_send_sessions_list(isg_net, from_pid, ev);
			break;

		case EVENT_SESS_GETCOUNT:
			isg_send_session_count(isg_net, from_pid);
			break;

		case EVENT_SESS_CLEAR:
			if (isg_clear_session(isg_net, ev)) {
				type = EVENT_KERNEL_NACK;
			} else {
				type = EVENT_KERNEL_ACK;
			}
			isg_send_event_type(isg_net, from_pid, type);
			break;

		case EVENT_NE_SWEEP_QUEUE:
			nehash_sweep_queue(isg_net);
			isg_send_event_type(isg_net, from_pid, EVENT_KERNEL_ACK);
			break;

		case EVENT_NE_ADD_QUEUE:
			nehash_add_to_queue(isg_net, ev->ne.pfx, ev->ne.mask, ev->ne.tc_name);
			isg_send_event_type(isg_net, from_pid, EVENT_KERNEL_ACK);
			break;

		case EVENT_NE_COMMIT:
			nehash_commit_queue(isg_net);
			isg_send_event_type(isg_net, from_pid, EVENT_KERNEL_ACK);
			break;

		case EVENT_SDESC_ADD:
			if (isg_add_service_desc(isg_net, ev->sdesc.service_name, ev->sdesc.tc_name)) {
				type = EVENT_KERNEL_NACK;
			} else {
				type = EVENT_KERNEL_ACK;
			}
			isg_send_event_type(isg_net, from_pid, type);
			break;

		case EVENT_SDESC_SWEEP_TC:
			isg_sweep_service_desc_tc(isg_net);
			isg_send_event_type(isg_net, from_pid, EVENT_KERNEL_ACK);
			break;

		case EVENT_SERV_GETLIST:
			isg_send_services_list(isg_net, from_pid, ev);
			break;

		default:
			printk(KERN_ERR "ipt_ISG: Unknown event type %d\n", ev->type);
	}
}

static void isg_nl_receive(struct sk_buff *skb) {
	//mutex_lock(&event_mutex);

	isg_nl_receive_skb(skb);
	//mutex_unlock(&event_mutex);
}

static void isg_send_skb(struct isg_net *isg_net, pid_t pid, struct sk_buff *skb) {
	int err;
	spin_lock_bh(&isg_lock);
	err = netlink_unicast(isg_net->sknl, skb, pid, MSG_DONTWAIT);
	spin_unlock_bh(&isg_lock);

	if (err < 0) {
		if (pid == isg_net->listener_pid) {
			if (err == -ECONNREFUSED) {
				printk(KERN_ERR "ipt_ISG: Listener daemon (pid %d) disappeared\n", isg_net->listener_pid);
				isg_net->listener_pid = 0;
			} else {
				printk(KERN_ERR "ipt_ISG: Lost packet during sending data to listener (err=%d)\n", err);
			}
		} else {
			printk(KERN_ERR "ipt_ISG: Error (%d) while sending response to pid %d\n", err, pid);
		}
	}

}

static struct sk_buff *isg_alloc_skb(struct isg_net *isg_net, unsigned int size) {
	struct sk_buff *skb = alloc_skb(size, GFP_ATOMIC);

	if (!skb) {
		printk(KERN_ERR "ipt_ISG: isg_alloc_skb() unable to alloc_skb\n");
	}

	return skb;
}

static inline struct isg_ev_session_stat isg_init_ev_stat(struct isg_session *is)
{
	struct isg_ev_session_stat res = { 0 };
	res.in_bytes    = is->stat[ISG_DIR_IN].bytes;
	res.in_packets  = is->stat[ISG_DIR_IN].packets;
	res.out_bytes   = is->stat[ISG_DIR_OUT].bytes;
	res.out_packets = is->stat[ISG_DIR_OUT].bytes;
	return res;
}

static struct sk_buff *isg_send_event(struct isg_net *isg_net, u_int16_t type,
			struct isg_session *is, pid_t pid, int nl_type, int nl_flags,
			struct sk_buff *skb) {
	struct isg_out_event *ev;
	struct nlmsghdr *nlh;
	void *nl_data;

	int data_size = sizeof(struct isg_out_event);
	int len = NLMSG_SPACE(data_size);

	if (pid == 0) {
		if (isg_net->listener_pid) {
			pid = isg_net->listener_pid;
		} else {
			return skb;
		}
	}

	ev = kzalloc(sizeof(struct isg_out_event), GFP_ATOMIC);
	if (!ev) {
		printk(KERN_ERR "ipt_ISG: isg_send_event() event allocation failed\n");
		goto alloc_fail;
	}

	ev->type = type;

	if (is) {
		isg_session_info_v0_fill(&ev->sinfo, &is->info);
		rcu_read_lock();
		isg_session_rate_info(&ev->sinfo, rcu_dereference(is->rate));
		rcu_read_unlock();

		ev->sstat = isg_init_ev_stat(is);

		if (is->start_ktime) {
			ev->sstat.duration = (u32)div_u64(ktime_get_mono_fast_ns() - is->start_ktime, NSEC_PER_SEC);
		}

		if (is->parent_is) {
			ev->parent_session_id = is->parent_is->info.id;
			memcpy(ev->sinfo.cookie, is->parent_is->info.cookie, 32);
		}

		if (is->sdesc) {
			memcpy(ev->service_name, is->sdesc->name, sizeof(is->sdesc->name));
		}
	}

	if (nl_flags & NLM_F_MULTI) {
		if (!skb) {
			if (!(skb = isg_alloc_skb(isg_net, NLMSG_GOODSIZE)))
				goto alloc_fail;
		} else {
			if (len > skb_tailroom(skb)) {
				isg_send_skb(isg_net, pid, skb);

				if (!(skb = isg_alloc_skb(isg_net, NLMSG_GOODSIZE)))
					goto alloc_fail;
			}
		}
	} else {
		if (!(skb = isg_alloc_skb(isg_net, len)))
			goto alloc_fail;
	}

	nlh = nlmsg_put(skb, 0, 0, nl_type, data_size, nl_flags);

	if (nlh == NULL) {
		goto alloc_fail;
	}

	nl_data = NLMSG_DATA(nlh);
	memcpy(nl_data, ev, data_size);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	NETLINK_CB(skb).portid = 0;
#else
	NETLINK_CB(skb).pid = 0;
#endif

	NETLINK_CB(skb).dst_group = 0;

	if (nl_type == NLMSG_DONE) {
		isg_send_skb(isg_net, pid, skb);
		skb = NULL;
	}

	kfree(ev);

	return skb;

alloc_fail:
	printk(KERN_ERR "ipt_ISG: SKB allocation failed\n");

	if (skb) {
		kfree_skb(skb);
		skb = NULL;
	}

	if (ev) {
		kfree(ev);
	}

	return skb;
}

static void isg_send_event_type(struct isg_net *isg_net, pid_t pid, u_int32_t type) {
	isg_send_event(isg_net, type, NULL, pid, NLMSG_DONE, 0, NULL);
}

static inline unsigned int get_isg_hash(u_int32_t val) {
	return jhash_1word(val, jhash_rnd) & (nr_buckets - 1);
}

/* MUST be called under read_lock of services_rw_lock */
static struct isg_service_desc *find_service_desc(struct isg_net *isg_net, u_int8_t *service_name) {
	struct isg_service_desc *sdesc;
	struct hlist_node *n;

	hlist_for_each_entry_safe(sdesc, n, &isg_net->services, list) {
		if (!strcmp(sdesc->name, service_name)) {
			return sdesc;
		}
	}

	return NULL;
}

static void isg_sweep_service_desc_tc(struct isg_net *isg_net) {
	struct isg_service_desc *sdesc;

	read_lock_bh(&isg_net->services_rw_lock);
	hlist_for_each_entry(sdesc, &isg_net->services, list) {
		if (!(sdesc->flags & SERVICE_DESC_IS_DYNAMIC)) {
			memset(sdesc->tcs, 0, sizeof(sdesc->tcs));
		}
	}
	read_unlock_bh(&isg_net->services_rw_lock);
}

static int isg_add_service_desc(struct isg_net *isg_net, u_int8_t *service_name, u_int8_t *tc_name) {
	struct traffic_class *tc = NULL;
	struct traffic_class **tc_list;
	struct isg_service_desc *sdesc;
	int i;

	isg_log("ipt_ISG: add service decription %s: tc %s", (char *)service_name, (char *) tc_name);
	read_lock_bh(&isg_net->nehash_rw_lock);
	tc = nehash_find_class(isg_net, tc_name);
	if (!tc) {
		printk(KERN_ERR "ipt_ISG: Unknown traffic class '%s' for service name '%s'\n", tc_name, service_name);
		goto err;
	}

	sdesc = find_service_desc(isg_net, service_name);
	if (!sdesc) {
		sdesc = kzalloc(sizeof(struct isg_service_desc), GFP_ATOMIC);
		if (!sdesc) {
			printk(KERN_ERR "ipt_ISG: service allocation failed\n");
			goto err;
		}

		memcpy(sdesc->name, service_name, sizeof(sdesc->name));
		write_lock_bh(&isg_net->services_rw_lock);
		hlist_add_head(&sdesc->list, &isg_net->services);
		write_unlock_bh(&isg_net->services_rw_lock);
	}

	tc_list = sdesc->tcs;

	for (i = 0; *tc_list && i < MAX_SD_CLASSES; i++) {
		if (*(tc_list++) == tc) {
			goto out;
		}
	}

	if (*tc_list) {
		printk(KERN_ERR "ipt_ISG: Can't add traffic class to service description\n");
		goto err;
	}

	*tc_list = tc;

out:
	read_unlock_bh(&isg_net->nehash_rw_lock);
	return 0;

err:
	read_unlock_bh(&isg_net->nehash_rw_lock);
	return 1;
}

static int isg_apply_service(struct isg_net *isg_net, struct isg_in_event *ev) {
	struct isg_session *is, *nis;
	struct isg_service_desc *sdesc;

	sdesc = find_service_desc(isg_net, ev->si.service_name);
	if (!sdesc) {
		printk(KERN_ERR "ipt_ISG: Unknown service name '%s'\n", ev->si.service_name);
		return 1;
	}

	is = isg_find_session(isg_net, ev);
	if (!is) {
		printk(KERN_ERR "ipt_ISG: Unable to find parent session\n");
		return 1;
	}

	isg_log("ipt_ISG: apply service %s to session Virtual%d", ev->si.service_name, is->info.port_number);

	nis = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
	if (!nis) {
		printk(KERN_ERR "ipt_ISG: service allocation failed\n");
		return 1;
	}

	spin_lock_init(&nis->lock);
	spin_lock_init(&nis->stat[0].lock);
	spin_lock_init(&nis->stat[1].lock);

	nis->parent_is = is;
	nis->info = is->info;
	nis->isg_net = is->isg_net;
	get_random_bytes(&(nis->info.id), sizeof(nis->info.id));

	nis->sdesc = sdesc;
	spin_lock_bh(&is->lock);
	hlist_add_head(&nis->srv_node, &is->srv_head);
	spin_unlock_bh(&is->lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
	setup_timer(&nis->timer, isg_session_timeout, (unsigned long)nis);
#else
	timer_setup(&nis->timer, isg_session_timeout, 0);
#endif
	mod_timer(&nis->timer, jiffies + session_check_interval * HZ);

	ev->si.sinfo.id = nis->info.id;
	__set_bit(ISG_IS_SERVICE, &ev->si.sinfo.flags);

	isg_update_session(isg_net, ev);

	return 0;

}

/* MUST be called under hlist lock */
static void __isg_insert_session(struct isg_net *isg_net, struct isg_session *is, unsigned int hash)
{
	struct hlist_bl_head *h;

	h = &isg_net->hash[hash];
	is->hash_key = hash;
	is->isg_net = isg_net;
	hlist_bl_add_head(&is->list, h);
}
/* MUST be called under hlist lock */
static struct isg_session *__isg_create_session(struct isg_net *isg_net, u32 ipaddr, unsigned int shash)
{
	struct isg_session_rate *rate;
	struct isg_session *is;

	is = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
	if (!is) {
		printk(KERN_ERR "ipt_ISG: session allocation failed\n");
		return NULL;
	}
	rate = kzalloc(sizeof(struct isg_session_rate) * 2, GFP_ATOMIC);
	if (!rate) {
		printk(KERN_ERR "ipt_ISG: session allocation failed\n");
		kfree(is);
		return NULL;
	}
	spin_lock_init(&is->lock);
	spin_lock_init(&is->stat[0].lock);
	spin_lock_init(&is->stat[1].lock);
	INIT_HLIST_HEAD(&is->srv_head);
	is->info.ipaddr = ipaddr;
	WRITE_ONCE(is->rate, rate);
	__isg_insert_session(isg_net, is, shash);

	return is;
}

/* Used for session fullfilment but with hlist unlocked */
static void isg_create_session_notify(struct isg_net *isg_net, struct isg_session *is, u8 *src_mac) {
	struct isg_net_stat *cnt;
	unsigned int port_number;

	is->start_ktime = ktime_get_mono_fast_ns();
	is->info.max_duration = INITIAL_MAX_DURATION;

	if (src_mac) {
		memcpy(is->info.macaddr, src_mac, ETH_ALEN);
	}

	get_random_bytes(&(is->info.id), sizeof(is->info.id));

	port_number = find_first_zero_bit(isg_net->port_bitmap, PORT_BITMAP_SIZE);
	while(test_and_set_bit(port_number, isg_net->port_bitmap)) {
		port_number = find_next_zero_bit(isg_net->port_bitmap, PORT_BITMAP_SIZE, port_number);
	}
	is->info.port_number = port_number;


	isg_log("ipt_ISG: create session Virtual%d", is->info.port_number);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
	setup_timer(&is->timer, isg_session_timeout, (unsigned long)is);
#else
	timer_setup(&is->timer, isg_session_timeout, 0);
#endif
	mod_timer(&is->timer, jiffies + session_check_interval * HZ);


	isg_send_event(isg_net, EVENT_SESS_CREATE, is, 0, NLMSG_DONE, 0, NULL);

	cnt = this_cpu_ptr(isg_net->cnt);
	cnt->unapproved++;
}

static int __isg_start_session(struct isg_session *is) {
	u64 ns_now;

	if (IS_SESSION_DYING(is))
		return 0;
	ns_now = ktime_get_mono_fast_ns();

	isg_log("ipt_ISG: start session Virtual%d", is->info.port_number);

	is->start_ktime = is->last_export = ns_now;

	memset(is->stat, 0, 2*sizeof(struct isg_session_stat));
	is->stat[ISG_DIR_IN].last_seen = ns_now;

	if (IS_SERVICE(is)) {
		set_bit(ISG_SERVICE_ONLINE, &is->info.flags);
	}

	mod_timer(&is->timer, jiffies + session_check_interval * HZ);

	return 1;
}

static inline int isg_start_session(struct isg_session *is) {
	int ret;

	spin_lock_bh(&is->lock);
	ret = __isg_start_session(is);
	spin_unlock_bh(&is->lock);

	if (ret)
		isg_send_event(is->isg_net, EVENT_SESS_START, is, 0, NLMSG_DONE, 0, NULL);

	return ret;
}


static int isg_update_session(struct isg_net *isg_net, struct isg_in_event *ev) {
	struct isg_session_rate *old_rate = NULL, *rate;
	struct isg_net_stat *cnt;
	struct isg_session *is;

	is = isg_find_session(isg_net, ev);

	if (!is) {
		return 1;
	}

	if (IS_SESSION_DYING(is)) {
		isg_log("ipt_ISG: update on dying session Virtual%d", is->info.port_number);
		return 1;
	}

	isg_log("ipt_ISG: update session Virtual%d", is->info.port_number);

	rate = kmalloc(sizeof(struct isg_session_rate) * 2, GFP_KERNEL);
	if (rate) {
		rate[ISG_DIR_IN] = ev->si.sinfo.rate[ISG_DIR_IN];
		rate[ISG_DIR_OUT] = ev->si.sinfo.rate[ISG_DIR_OUT];
		old_rate = is->rate;
		rcu_assign_pointer(is->rate, rate);
	} else
		printk(KERN_ERR "ipt_ISG: No memore to allocate rate info for Virtual%d\n", is->info.port_number);

	spin_lock_bh(&is->lock);
	if (!is->info.flags) {
		is->info.max_duration = 0;
	}

	isg_session_info_v1_fill_timeouts(&is->info, &ev->si.sinfo);

	if (ev->si.sinfo.nat_ipaddr) {
		is->info.nat_ipaddr = ev->si.sinfo.nat_ipaddr;
	}

	if (ev->si.sinfo.flags & FLAGS_ALL_MASK) {
		unsigned long flags = ev->si.sinfo.flags & FLAGS_RW_MASK;

		if (!ev->si.flags_op) {
			is->info.flags = flags;
		} else if (ev->si.flags_op == FLAG_OP_SET) {
			is->info.flags |= flags;
		} else if (ev->si.flags_op == FLAG_OP_UNSET) {
			is->info.flags &= ~flags;
		}
	}

	if (ev->type == EVENT_SERV_APPLY) {
		set_bit(ISG_IS_SERVICE, &is->info.flags);
	} else if (ev->type == EVENT_SESS_APPROVE) {
		memcpy(is->info.cookie, ev->si.sinfo.cookie, 32);
		if (!test_and_set_bit(ISG_IS_APPROVED, &is->info.flags)) {
			cnt = this_cpu_ptr(isg_net->cnt);
			cnt->approved++;
			cnt->unapproved--;
		}
		__isg_start_session(is);
	}
	spin_unlock_bh(&is->lock);

	if (old_rate)
		kfree_rcu(old_rate);
	if (ev->type == EVENT_SESS_APPROVE) {
		isg_send_event(is->isg_net, EVENT_SESS_START, is, 0, NLMSG_DONE, 0, NULL);
	}

	return 0;
}

static int isg_free_session(struct isg_session *is) {
	struct isg_net_stat *cnt;
	struct hlist_bl_head *h;
	struct isg_session *isrv;
	struct hlist_node *n;

	if (!IS_SERVICE(is)) {
		isg_log("ipt_ISG: free session %d", is->info.port_number);
		h = &is->isg_net->hash[is->hash_key];
		set_bit(ISG_IS_DYING, &is->info.flags);
		local_bh_disable();
		hlist_bl_lock(h);
		hlist_bl_del_init(&is->list);
		hlist_bl_unlock(h);
		local_bh_enable();
		if (is->info.port_number) {
			clear_bit(is->info.port_number, is->isg_net->port_bitmap);
		}
		cnt = this_cpu_ptr(is->isg_net->cnt);
		cnt->approved -= !!IS_SESSION_APPROVED(is);
		cnt->unapproved -= !IS_SESSION_APPROVED(is);
		cnt->dying++;
	}

	if (!hlist_empty(&is->srv_head)) { /* Freeing sub-sessions also */

		hlist_for_each_entry_safe(isrv, n, &is->srv_head, srv_node) {
			if (test_and_clear_bit(ISG_SERVICE_ONLINE, &isrv->info.flags)) {
				isg_send_event(isrv->isg_net, EVENT_SESS_STOP, isrv, 0, NLMSG_DONE, 0, NULL);
			}
			del_timer(&isrv->timer);
		}
	}

	if (is->info.flags) {
		isg_send_event(is->isg_net, EVENT_SESS_STOP, is, 0, NLMSG_DONE, 0, NULL);
	}
	mod_timer(&is->timer, jiffies + 2*HZ);
	return 0;
}

static int isg_clear_session(struct isg_net *isg_net, struct isg_in_event *ev) {
	struct isg_session *is;

	is = isg_find_session(isg_net, ev);
	if (is) {
		isg_log("ipt_ISG: clear session %d", is->info.port_number);
		isg_free_session(is);
		return 0;
	}
	return 1;
}

/* should be called under bit locked list */
static inline struct isg_session *isg_lookup_session_hash(struct isg_net *isg_net,
                u_int32_t ipaddr, unsigned int h) {
	struct isg_session *is;
	struct hlist_bl_node *l, *c;
	hlist_bl_for_each_entry_safe(is, l, c, &isg_net->hash[h], list) {
		if (is->info.ipaddr == ipaddr) {
			return is;
		}
	}

	return NULL;
}

static inline struct isg_session *isg_lookup_session(struct isg_net *isg_net, u_int32_t ipaddr) {
	struct isg_session *is;
	struct hlist_bl_node *l, *c;

	unsigned int h = get_isg_hash(ipaddr);

	hlist_bl_for_each_entry_safe(is, l, c, &isg_net->hash[h], list) {
		if (is->info.ipaddr == ipaddr) {
			return is;
		}
	}

	return NULL;
}

static inline int isg_equal(struct isg_in_event *ev, struct isg_session *is) {
	if ((ev->si.sinfo.id && ev->si.sinfo.id == is->info.id) ||
	    (is->info.port_number == ev->si.sinfo.port_number) ||
	    (is->info.ipaddr == ev->si.sinfo.ipaddr)) {
		return 1;
	} else {
		return 0;
	}
}

static struct isg_session *isg_find_session(struct isg_net *isg_net, struct isg_in_event *ev) {
	unsigned int i;
	struct isg_session *is;
	struct hlist_bl_node *l, *c;

	for (i = 0; i < nr_buckets; i++) {
		hlist_bl_for_each_entry_safe(is, l, c, &isg_net->hash[i], list) {
			if (test_bit(ISG_IS_SERVICE, &ev->si.sinfo.flags)) {
				/* Searching for sub-session (service) */
				if (!hlist_empty(&is->srv_head)) {
					struct isg_session *isrv;

					hlist_for_each_entry(isrv, &is->srv_head, srv_node) {
						if (isg_equal(ev, isrv)) {
							return isrv;
						}
					}
				}
			} else {
				/* Searching for session (only heads) */
				if (isg_equal(ev, is)) {
					return is;
				}
			}
		}
	}
	return NULL;
}

static void isg_send_sessions_list(struct isg_net *isg_net, pid_t pid, struct isg_in_event *ev) {
	unsigned int i;
	struct isg_session *is = NULL;
	struct hlist_bl_node *l, *n;
	struct sk_buff *skb = NULL;

	if (ev->si.sinfo.port_number || ev->si.sinfo.id) {
		is = isg_find_session(isg_net, ev);
		isg_send_event(isg_net, EVENT_SESS_INFO, is, pid, NLMSG_DONE, 0, NULL);
	} else {
		for (i = 0; i < nr_buckets; i++) {
			hlist_bl_for_each_entry_safe(is, l, n, &isg_net->hash[i], list) {
				skb = isg_send_event(isg_net, EVENT_SESS_INFO, is, pid, 0, NLM_F_MULTI, skb);
				if (unlikely(!skb)) {
					pr_warn("ipt_ISG: Error in allocation while sending session list");
				}
			}
		}
		isg_send_event(isg_net, EVENT_SESS_INFO, NULL, pid, NLMSG_DONE, NLM_F_MULTI, skb);
	}
}

static void isg_send_session_count(struct isg_net *isg_net, pid_t pid) {
	struct isg_session *nis;
	int i;

	nis = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
	if (!nis) {
		printk(KERN_ERR "ipt_ISG: session allocation failed\n");
		return;
	}

	spin_lock_init(&nis->lock);
	for_each_possible_cpu(i) {
		struct isg_net_stat *cnt;
		cnt = per_cpu_ptr(isg_net->cnt, i);
		nis->info.ipaddr += cnt->approved;
		nis->info.nat_ipaddr += cnt->unapproved;
		nis->info.port_number += cnt->dying;
	}
	isg_send_event(isg_net, EVENT_SESS_COUNT, nis, pid, NLMSG_DONE, 0, NULL);

	kfree(nis);

}

static void isg_send_services_list(struct isg_net *isg_net, pid_t pid, struct isg_in_event *ev) {
	struct isg_session *is, *isrv;
	struct sk_buff *skb = NULL;

	is = isg_find_session(isg_net, ev);

	if (is && !hlist_empty(&is->srv_head)) {
		hlist_for_each_entry(isrv, &is->srv_head, srv_node) {
			skb = isg_send_event(isg_net, EVENT_SESS_INFO, isrv, pid, 0, NLM_F_MULTI, skb);
		}
	}

	isg_send_event(isg_net, EVENT_SESS_INFO, NULL, pid, NLMSG_DONE, NLM_F_MULTI, skb);

}

/* MUST be called under session stat spinlock locked */
static inline void __isg_update_tokens(struct isg_session_stat *iss, u64 now,
			u32 rate, u32 burst)
{
	u64 tokens, us_after;

	/* we will use microseconds precision to avoid overflows */
	us_after = time_after64(now, iss->last_seen) ? div_u64(now - iss->last_seen, NSEC_PER_USEC) : 0;
	tokens = mul_u64_u32_div(us_after, rate, USEC_PER_SEC);

	if ((iss->tokens + tokens) > burst) {
		iss->tokens = burst;
	} else {
		iss->tokens += tokens;
	}

	iss->last_seen += us_after * NSEC_PER_USEC;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void isg_session_timeout(unsigned long arg) {
	struct isg_session *is = (struct isg_session *) arg;
#else
static void isg_session_timeout(struct timer_list *arg) {
	struct isg_session *is = from_timer(is, arg, timer);
#endif
	u64 ns_now, stat_duration, idle_nsec, last_seen;
	struct isg_net_stat *cnt;
	struct isg_session *isrv;
	struct hlist_node *l;

	if (module_exiting) {
		return;
	}

	if (IS_SESSION_DYING(is)) {
		isg_log("ipt_ISG: Virtual%d ISG_IS_DYING, freeing", is->info.port_number);
		if (!hlist_empty(&is->srv_head)) {
			hlist_for_each_entry_safe(isrv, l, &is->srv_head, srv_node) {
				hlist_del(&isrv->srv_node);
				kfree(isrv);
			}
		}
		cnt = this_cpu_ptr(is->isg_net->cnt);
		cnt->dying--;
		kfree_rcu(is->rate);
		kfree(is);
		return;
	}

	ns_now = ktime_get_mono_fast_ns();

	stat_duration = ns_now - is->start_ktime;
	last_seen = max(is->stat[ISG_DIR_IN].last_seen, is->stat[ISG_DIR_OUT].last_seen);
	idle_nsec = ns_now - last_seen;

	if (IS_SERVICE_ONLINE(is)) { /* Service timeout */

		/* Check maximum session duration and idle timeout */
		if ((is->info.max_duration && stat_duration >= is->info.max_duration) ||
		    (is->info.idle_timeout && idle_nsec >= is->info.idle_timeout)) {
			clear_bit(ISG_SERVICE_ONLINE, &is->info.flags);
			spin_lock_bh(&is->lock);
			get_random_bytes(&(is->info.id), sizeof(is->info.id));
			is->start_ktime = 0;
			memset(is->stat, 0, 2*sizeof(struct isg_session_stat));
			spin_unlock_bh(&is->lock);
		} else {
			/* session service is active */
			mod_timer(&is->timer, jiffies + session_check_interval * HZ);
		}
	} else if (!IS_SERVICE(is)) { /* Session timeout */

		//call something like isg_free_session
		if (!is->info.flags && stat_duration >= is->info.max_duration) {
			isg_free_session(is);
			goto out;
		} else if (IS_SESSION_APPROVED(is)) {

			spin_lock_bh(&is->lock);

			if (unlikely(!hlist_empty(&is->srv_head))) {
				hlist_for_each_entry_safe(isrv, l, &is->srv_head, srv_node) {
					is->stat[ISG_DIR_IN].last_seen = max(is->stat[ISG_DIR_IN].last_seen,
									isrv->stat[ISG_DIR_IN].last_seen);
					is->stat[ISG_DIR_OUT].last_seen = max(is->stat[ISG_DIR_OUT].last_seen,
									isrv->stat[ISG_DIR_OUT].last_seen);
				}
				/* Service might have been seen later */
				last_seen = max(is->stat[ISG_DIR_IN].last_seen, is->stat[ISG_DIR_OUT].last_seen);
				idle_nsec = ns_now - last_seen;
			}

			spin_unlock_bh(&is->lock);

			/* Check maximum session duration and idle timeout */
			if ((is->info.max_duration && stat_duration >= is->info.max_duration) ||
				(is->info.idle_timeout && idle_nsec >= is->info.idle_timeout)) {
				isg_free_session(is);
				goto out;
			/* Check last export time */
			} else if (is->info.export_interval && ns_now - is->last_export >= is->info.export_interval) {
				is->last_export = ns_now;
				isg_send_event(is->isg_net, EVENT_SESS_UPDATE, is, 0, NLMSG_DONE, 0, NULL);
			}
		}	
		mod_timer(&is->timer, jiffies + session_check_interval * HZ);

	}

out:
	return;
}

static bool
isg_mt(const struct sk_buff *skb,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	const struct xt_match_param *par)
#else
	struct xt_action_param *par)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	const struct ipt_ISG_mt_info *iinfo = par->matchinfo;
#else
	const struct ipt_ISG_mt_info *iinfo = par->targinfo;
#endif
	bool err = 0;
	struct iphdr *iph;
	struct isg_session *is, *isrv;
	struct isg_net *isg_net;
	struct hlist_node *l;
	unsigned int shash;

	iph = ip_hdr(skb);

	isg_net = isg_pernet(dev_net((xt_in(par) != NULL) ? xt_in(par) : xt_out(par)));

	shash = get_isg_hash(iph->saddr);

	is = isg_lookup_session_hash(isg_net, iph->saddr, shash);
	if (!is)
		return 0;

	if (iinfo->flags) {
		if (!hlist_empty(&is->srv_head))
			return 0;
		if (IS_SESSION_APPROVED(is) == !!(iinfo->flags & ACTIVE_SESSION))
			return 1;
	}

	if (!hlist_empty(&is->srv_head)) {
		struct nehash_entry *ne;
		struct traffic_class **tc_list;

		read_lock_bh(&is->isg_net->nehash_rw_lock);
		ne = nehash_lookup(is->isg_net, iph->daddr);
		if (ne == NULL)
			goto out;

		hlist_for_each_entry_safe(isrv, l, &is->srv_head, srv_node) { /* For each sub-session (service) */
			int i;

			if (!test_bit(ISG_SERVICE_STATUS_ON, &isrv->info.flags) || !test_bit(ISG_SERVICE_TAGGER, &isrv->info.flags)) {
				continue;
			}
			if (strncmp(isrv->sdesc->name, iinfo->service_name, MAX_SERVICE_NAME))
				continue;

			tc_list = isrv->sdesc->tcs;

			for (i = 0; *tc_list && i < MAX_SD_CLASSES; i++, tc_list++) { /* For each service description's class */
				struct traffic_class *tc = *tc_list;
		
				if (ne->tc == tc) {
					err = 1;
					goto out;
				}
			}
			break;
		}
out:
		read_unlock_bh(&is->isg_net->nehash_rw_lock);
	}

	return err;
}

static unsigned int
isg_tg(struct sk_buff *skb,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	const struct xt_target_param *par)
#else
	const struct xt_action_param *par)
#endif
{
	const struct ipt_ISG_info *iinfo = par->targinfo;
	struct isg_session_stat *stat;
	struct isg_session_rate *srate;

	struct iphdr *iph;
	struct isg_session *is, *isrv, *parent_is = NULL;
	struct nehash_entry *ne;
	struct traffic_class **tc_list;
	__be32 laddr, raddr;
	struct isg_net *isg_net = isg_pernet(dev_net((xt_in(par) != NULL) ?
				xt_in(par) : xt_out(par))); 
	struct isg_net *iisg_net;
	unsigned int shash;
	int dir;
	const unsigned int action_accept =
		isg_net->tg_permit_action ? NF_ACCEPT : XT_CONTINUE;
	const unsigned int action_drop =
		isg_net->tg_deny_action ? XT_CONTINUE : NF_DROP;
	unsigned int action = action_drop;

	u32 pkt_len, pkt_len_bits, rate, burst;
	u64 now;

	iph = ip_hdr(skb);

	pkt_len = ntohs(iph->tot_len);

	now = ktime_get_mono_fast_ns();

	pkt_len_bits = pkt_len << 3;

	if (iinfo->flags & INIT_BY_SRC) { /* Init direction */
		laddr = iph->saddr;
		raddr = iph->daddr;
		dir = ISG_DIR_IN;
	} else {
		laddr = iph->daddr;
		raddr = iph->saddr;
		dir = ISG_DIR_OUT;
	}

	shash = get_isg_hash(laddr);
	hlist_bl_lock(&isg_net->hash[shash]);

	is = isg_lookup_session_hash(isg_net, laddr, shash);

	if (is == NULL) {
		/* assume action = action_drop; */
		if (iinfo->flags & INIT_SESSION) {
			is = __isg_create_session(isg_net, laddr, shash);
		} else if (isg_net->pass_outgoing) {
			action = action_accept;
		}
		hlist_bl_unlock(&isg_net->hash[shash]);

		if (is) {
			u8 *src_mac = NULL;

			if (skb_mac_header_was_set(skb) && iinfo->flags & INIT_BY_SRC) {
				src_mac = eth_hdr(skb)->h_source;
			}

			isg_create_session_notify(isg_net, is, src_mac);
		}

		goto out;
	}
	hlist_bl_unlock(&isg_net->hash[shash]);

	if (!is->info.flags) {
		/* assume action = action_drop; */
		goto out;
	}

	prefetchw(is->stat);
	if (unlikely(!hlist_empty(&is->srv_head))) {
		/* This session is having sub-sessions, try to classify */
		iisg_net = is->isg_net;
		read_lock_bh(&iisg_net->nehash_rw_lock);
		ne = nehash_lookup(iisg_net, raddr);
		if (ne == NULL) {
			read_unlock_bh(&iisg_net->nehash_rw_lock);
			/* assume action = action_drop; */
			goto out;
		}


		hlist_for_each_entry(isrv, &is->srv_head, srv_node) { /* For each sub-session */
			int i;

			if (!test_bit(ISG_SERVICE_STATUS_ON, &isrv->info.flags) || test_bit(ISG_SERVICE_TAGGER, &isrv->info.flags)) {
				continue;
			}

			tc_list = isrv->sdesc->tcs;

			for (i = 0; *tc_list && i < MAX_SD_CLASSES; i++, tc_list++) { /* For each service description's class */
				struct traffic_class *tc = *tc_list;
				if (ne->tc == tc) {
					parent_is = is;
					is = isrv;
					break;
				}
			}
			if (parent_is) {
				break;
			}
		}

		read_unlock_bh(&iisg_net->nehash_rw_lock);
		if (!parent_is) {
			/* This packet doesn't belongs to session's services (or appropriate service's status is not on) */
			/* assume action = action_drop; */
			goto out;
		}
		prefetchw(is->stat);
		if (!test_bit(ISG_SERVICE_ONLINE, &is->info.flags)) {
			isg_start_session(is);
		}
	}

	stat = &is->stat[dir];

	rcu_read_lock();
	srate = rcu_dereference(is->rate);
	rate = srate[dir].rate;
	burst = srate[dir].burst;
	rcu_read_unlock();

	spin_lock_bh(&stat->lock);
	__isg_update_tokens(stat, now, rate, burst);

	if (pkt_len_bits <= stat->tokens || !rate) {
		stat->tokens -= pkt_len_bits;

		stat->bytes += pkt_len;
		stat->packets++;

		action = action_accept;
	}
	/* default action drop */
	spin_unlock_bh(&stat->lock);

	if (parent_is && action == action_accept) {
		stat = &parent_is->stat[dir];
		spin_lock_bh(&stat->lock);
		stat->bytes += pkt_len;
		stat->packets++;
		spin_unlock_bh(&stat->lock);
	}

out:
	return action;
}

static int isg_initialize(struct net *net) {
	unsigned int i;
	int hsize = sizeof(struct hlist_head) * nr_buckets;

	struct isg_net *isg_net = isg_pernet(net);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	struct netlink_kernel_cfg cfg = {
		.groups = 0,
		.input = isg_nl_receive,
	};
#endif

	isg_net->tg_permit_action = tg_permit_action;
	isg_net->tg_deny_action = tg_deny_action;
	isg_net->pass_outgoing = pass_outgoing;

	isg_net->hash = vmalloc(hsize);
	if (isg_net->hash == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < nr_buckets; i++) {
		INIT_HLIST_BL_HEAD(&isg_net->hash[i]);
	}

	INIT_HLIST_HEAD(&isg_net->services);
	rwlock_init(&isg_net->services_rw_lock);

	isg_net->port_bitmap = vmalloc(BITS_TO_LONGS(PORT_BITMAP_SIZE) * sizeof(unsigned long));
	if (isg_net->port_bitmap == NULL) {
		return -ENOMEM;
	}

	bitmap_zero(isg_net->port_bitmap, PORT_BITMAP_SIZE);

	if (nehash_init(isg_net) < 0) {
		printk(KERN_ERR "ipt_ISG: Unable to initialize network hash table\n");
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	isg_net->sknl = netlink_kernel_create(net, ISG_NETLINK_MAIN, &cfg);
#else
	isg_net->sknl = netlink_kernel_create(net, ISG_NETLINK_MAIN, 0, isg_nl_receive, NULL, THIS_MODULE);
#endif

	if (isg_net->sknl == NULL) {
		printk(KERN_ERR "ipt_ISG: Can't create ISG_NETLINK_MAIN socket\n");
		return -1;
	}

	return 0;
}

void isg_cleanup(struct isg_net *isg_net) {
	unsigned int i;
	struct isg_session *is;
	struct isg_session_rate *rate;
	struct isg_service_desc *sdesc;
	struct hlist_bl_node *l, *c;
	struct hlist_node *n;

	isg_net->listener_pid = 0;

	if (isg_net->sknl != NULL) {
		netlink_kernel_release(isg_net->sknl);
	}

	for (i = 0; i < nr_buckets; i++) {
		hlist_bl_for_each_entry_safe(is, l, c, &isg_net->hash[i], list) {
			isg_free_session(is);
			del_timer(&is->timer);
			rate = is->rate;
			rcu_assign_pointer(is->rate, NULL);
			kfree(is);
			if (rate)
				kfree_rcu(rate);
		}
	}

	write_lock_bh(&isg_net->services_rw_lock);
	hlist_for_each_entry_safe(sdesc, n, &isg_net->services, list) {
		hlist_del(&sdesc->list);
		kfree(sdesc);
	}
	write_unlock_bh(&isg_net->services_rw_lock);

	nehash_free_everything(isg_net);

	vfree(isg_net->hash);
	vfree(isg_net->port_bitmap);
	free_percpu(isg_net->cnt);
}

static int __net_init isg_net_init(struct net *net) {
	struct isg_net *isg_net;
	struct ctl_table *table;
	int err = -ENOMEM, i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	isg_net = kzalloc(sizeof(struct isg_net), GFP_KERNEL);
	if (isg_net == NULL) {
		goto err_alloc;
	}

	err = net_assign_generic(net, isg_net_id, isg_net);
	if (err < 0) {
		goto err_assign;
	}
#endif

	isg_net = isg_pernet(net);

	table = kmemdup(isg_net_table, sizeof(isg_net_table), GFP_KERNEL);
	if (table == NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	goto err_assign;
#else
	return -ENOMEM;
#endif
	}

	table[0].data = &isg_net->tg_permit_action;
	table[1].data = &isg_net->tg_deny_action;
	table[2].data = &isg_net->pass_outgoing;

	isg_net->cnt = alloc_percpu_gfp(struct isg_net_stat, GFP_KERNEL);
	if (!isg_net->cnt)
		goto err_reg;
	for_each_possible_cpu(i) {
		struct isg_net_stat *cnt = per_cpu_ptr(isg_net->cnt, i);
		cnt->approved = 0;
		cnt->unapproved = 0;
		cnt->dying = 0;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	isg_net->sysctl_hdr = register_net_sysctl(net, "net/ipt_ISG", table);
#else
	isg_net->sysctl_hdr = register_net_sysctl_table(net, net_ipt_isg_ctl_path, table);
#endif
	if (isg_net->sysctl_hdr == NULL) {
		err = -ENOMEM;
		goto err_stats;
	}

	err = isg_initialize(net);
	if (err < 0) {
		goto err_init;
	}

	return 0;

err_init:
	unregister_net_sysctl_table(isg_net->sysctl_hdr);
err_stats:
	free_percpu(isg_net->cnt);
err_reg:
	kfree(table);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
err_assign:
	kfree(isg_net);
err_alloc:
	return err;
#else
	return err;
#endif
}

static void __net_exit isg_net_exit(struct net *net) {
	struct isg_net *isg_net = isg_pernet(net);
	struct ctl_table *table;

	isg_cleanup(isg_net);

	table = isg_net->sysctl_hdr->ctl_table_arg;
	unregister_net_sysctl_table(isg_net->sysctl_hdr);
	kfree(table);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	kfree(isg_net);
#endif
}

static struct pernet_operations isg_net_ops = {
	.init = isg_net_init,
	.exit = isg_net_exit,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	.id   = &isg_net_id,
	.size = sizeof(struct isg_net),
#endif
};

static struct xt_target isg_tg_reg __read_mostly = {
	.name       = "ISG",
	.family     = NFPROTO_IPV4,
	.target     = isg_tg,
	.targetsize = sizeof(struct ipt_ISG_info),
	.me         = THIS_MODULE,
};

static struct xt_match isg_mt_reg __read_mostly = {
	.name       = "isg",
	.family     = NFPROTO_IPV4,
	.match      = isg_mt,
	.matchsize  = sizeof(struct ipt_ISG_mt_info),
	.me         = THIS_MODULE,
};

static int __init isg_tg_init(void) {
	int err;

	get_random_bytes(&jhash_rnd, sizeof(jhash_rnd));

	isg_sysctl_hdr = register_sysctl_paths(net_ipt_isg_ctl_path, empty_ctl_table);
	if (isg_sysctl_hdr == NULL) {
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	err = register_pernet_gen_subsys(&isg_net_id, &isg_net_ops);
#else /* < 2.6.33 */
	err = register_pernet_subsys(&isg_net_ops);
#endif

	if (err < 0) {
		return err;
	}

	printk(KERN_INFO "ipt_ISG: Loaded (built on %s)\n", _BUILD_DATE);

	err = xt_register_target(&isg_tg_reg);
	if (err < 0) {
		return err;
	}

	err = xt_register_match(&isg_mt_reg);
	if (err < 0) {
		xt_unregister_target(&isg_tg_reg);
		return err;
	}

	return 0;
}

static void __exit isg_tg_exit(void) {
	module_exiting = 1;

	xt_unregister_match(&isg_mt_reg);
	xt_unregister_target(&isg_tg_reg);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	unregister_pernet_gen_subsys(isg_net_id, &isg_net_ops);
#else /* < 2.6.33 */
	unregister_pernet_subsys(&isg_net_ops);
#endif
	unregister_sysctl_table(isg_sysctl_hdr);

	printk(KERN_INFO "ipt_ISG: Unloaded\n");
}

module_init(isg_tg_init);
module_exit(isg_tg_exit);

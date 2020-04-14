#ifndef _IP_ISG_H
#define _IP_ISG_H

#include <linux/version.h>
#include <linux/module.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/list_bl.h>

#include "isg.h"
#include "kcompat.h"

#define ISG_NETLINK_MAIN     MAX_LINKS - 1
#define PORT_BITMAP_SIZE     65536
#define INITIAL_MAX_DURATION 60
#define MAX_SD_CLASSES       16

#define ISG_DIR_IN    0x01
#define ISG_DIR_OUT   0x02

/* From Userspace to Kernel */
#define	EVENT_LISTENER_REG   0x01
#define	EVENT_LISTENER_UNREG 0x02
#define	EVENT_SESS_APPROVE   0x04
#define	EVENT_SESS_CHANGE    0x05
#define	EVENT_SESS_CLEAR     0x09
#define	EVENT_SESS_GETLIST   0x10
#define	EVENT_SESS_GETCOUNT  0x12
#define	EVENT_NE_ADD_QUEUE   0x14
#define	EVENT_NE_SWEEP_QUEUE 0x15
#define	EVENT_NE_COMMIT      0x16
#define	EVENT_SERV_APPLY     0x17
#define	EVENT_SDESC_ADD      0x18
#define	EVENT_SDESC_SWEEP_TC 0x19
#define	EVENT_SERV_GETLIST   0x20

/* From Kernel to Userspace */
#define	EVENT_SESS_CREATE  0x03
#define	EVENT_SESS_START   0x06
#define	EVENT_SESS_UPDATE  0x07
#define	EVENT_SESS_STOP    0x08
#define	EVENT_SESS_INFO    0x11
#define	EVENT_SESS_COUNT   0x13

#define	EVENT_KERNEL_ACK  0x98
#define	EVENT_KERNEL_NACK 0x99

#define ISG_IS_APPROVED        (1 << 0)
#define ISG_IS_SERVICE         (1 << 1)
#define ISG_SERVICE_STATUS_ON  (1 << 2)
#define ISG_SERVICE_ONLINE     (1 << 3)
#define ISG_NO_ACCT            (1 << 4)
#define ISG_IS_DYING           (1 << 5)
#define ISG_SERVICE_TAGGER     (1 << 6)

#define FLAGS_RW_MASK 0x54 /* (01010100) */

#define IS_SERVICE(is)				\
			(is->info.flags & ISG_IS_SERVICE)

#define IS_SERVICE_ONLINE(is)			\
			(IS_SERVICE(is) &&		\
			is->info.flags & ISG_SERVICE_ONLINE)

#define IS_SESSION_APPROVED(is)			\
			(is->info.flags & ISG_IS_APPROVED)

struct isg_session_info {
	u_int64_t id;
	u_int8_t cookie[32];

	u_int32_t ipaddr;			/* User's IP-address */
	u_int32_t nat_ipaddr;		/* User's 1-to-1 NAT IP-address */
	u_int8_t macaddr[ETH_ALEN];	/* User's MAC-address */

	u_int16_t flags;

	u_int32_t port_number;		/* Virtual port number for session */
	u_int32_t export_interval;	/* Session statistics export interval (in seconds) */
	u_int32_t idle_timeout;
	u_int32_t max_duration;

	u_int32_t in_rate;			/* Policing (rate/burst) info (kbit/s) */
	u_int32_t in_burst;
	u_int32_t out_rate;
	u_int32_t out_burst;
};

struct isg_session_stat {
	u_int32_t duration;		/* Session duration (seconds) */
	u_int32_t padding;		/* For in_packets field proper alignment on 64-bit systems */

	u_int64_t in_packets;	/* Statistics for session traffic */
	u_int64_t in_bytes;
	u_int64_t out_packets;
	u_int64_t out_bytes;
};

struct isg_session {
	struct isg_session_info info;
	struct isg_session_stat stat;

	u_int64_t in_tokens;
	u_int64_t out_tokens;

	u_int64_t in_last_seen;
	u_int64_t out_last_seen;

	time_t start_ktime;
	time_t last_export;

	struct timer_list timer;

	struct hlist_node list;			/* Main list of sessions (isg_hash) */
	struct isg_service_desc *sdesc;	/* Service description for this sub-session */
	struct isg_session *parent_is;	/* Parent session (only for sub-sessions/services) */

	struct hlist_head srv_head;		/* This session sub-sessions (services) list */
	struct hlist_node srv_node;

	struct isg_net *isg_net;
};

struct isg_in_event {
	u_int32_t type;
	union {
		struct isg_session_info_in {
			struct isg_session_info sinfo;
			u_int8_t service_name[32];
			u_int8_t flags_op;
#define FLAG_OP_SET   0x01
#define FLAG_OP_UNSET 0x02
		} __attribute__ ((packed)) si;

		struct nehash_entry_in {
			u_int32_t pfx;
			u_int32_t mask;
			u_int8_t tc_name[32];
		} __attribute__ ((packed)) ne;

		struct service_desc_in {
			u_int8_t tc_name[32];
			u_int8_t service_name[32];
			u_int8_t flags;
		} __attribute__ ((packed)) sdesc;
	};
} __attribute__ ((packed));

struct isg_out_event {
	u_int32_t type;
	struct isg_session_info sinfo;
	struct isg_session_stat sstat;
	u_int64_t parent_session_id;	/* Parent session-ID (only for sub-sessions/services) */
	u_int8_t service_name[32];		/* Service name (only for sub-sessions/services) */
} __attribute__ ((packed));

struct traffic_class {
	struct hlist_node list;
	u_int8_t name[32];
};

struct nehash_entry {
	struct hlist_node list;
	u_int32_t pfx;
	u_int32_t mask;
	struct traffic_class *tc;
};

struct isg_service_desc {
	struct hlist_node list;
	u_int8_t name[32];
	u_int8_t flags;
#define SERVICE_DESC_IS_DYNAMIC	(1 << 0)
	struct traffic_class *tcs[MAX_SD_CLASSES];
};

struct isg_net {
	struct hlist_bl_head *hash;

	struct hlist_head *nehash;
	struct hlist_head nehash_queue;
	struct hlist_head traffic_class;
	struct hlist_head services;

	struct sock *sknl;
	struct sk_buff *sskb;
	pid_t listener_pid;

	unsigned long *port_bitmap;

	struct ctl_table_header *sysctl_hdr;

	unsigned int approve_retry_interval;
	unsigned int tg_permit_action;
	unsigned int tg_deny_action;
	unsigned int pass_outgoing;
	rwlock_t nehash_rw_lock;
};

extern unsigned int nehash_key_len;
extern spinlock_t isg_lock;

extern int nehash_init(struct isg_net *);
extern int nehash_add_to_queue(struct isg_net *, u_int32_t, u_int32_t, u_int8_t *);
extern int nehash_commit_queue(struct isg_net *);
extern struct nehash_entry *nehash_lookup(struct isg_net *, u_int32_t);
extern void nehash_sweep_queue(struct isg_net *);
extern void nehash_sweep_entries(struct isg_net *);
extern void nehash_free_everything(struct isg_net *);
extern struct traffic_class *nehash_find_class(struct isg_net *, u_int8_t *);

#endif

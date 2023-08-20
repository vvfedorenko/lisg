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

#define ISG_DIR_IN    0x00
#define ISG_DIR_OUT   0x01

/* From Userspace to Kernel */
#define	EVENT_LISTENER_REG    0x01
#define	EVENT_LISTENER_REG_V1 0x101
#define	EVENT_LISTENER_UNREG  0x02
#define	EVENT_SESS_APPROVE    0x04
#define	EVENT_SESS_CHANGE     0x05
#define	EVENT_SESS_CLEAR      0x09
#define	EVENT_SESS_GETLIST    0x10
#define	EVENT_SESS_GETCOUNT   0x12
#define	EVENT_NE_ADD_QUEUE    0x14
#define	EVENT_NE_SWEEP_QUEUE  0x15
#define	EVENT_NE_COMMIT       0x16
#define	EVENT_SERV_APPLY      0x17
#define	EVENT_SDESC_ADD       0x18
#define	EVENT_SDESC_SWEEP_TC  0x19
#define	EVENT_SERV_GETLIST    0x20

/* From Kernel to Userspace */
#define	EVENT_SESS_CREATE  0x03
#define	EVENT_SESS_START   0x06
#define	EVENT_SESS_UPDATE  0x07
#define	EVENT_SESS_STOP    0x08
#define	EVENT_SESS_INFO    0x11
#define	EVENT_SESS_COUNT   0x13

#define	EVENT_KERNEL_ACK  0x98
#define	EVENT_KERNEL_NACK 0x99

enum isg_service_flags {
	ISG_IS_APPROVED,
	ISG_IS_SERVICE,
	ISG_SERVICE_STATUS_ON,
	ISG_SERVICE_ONLINE,
	ISG_NO_ACCT,
	ISG_IS_DYING,
	ISG_SERVICE_TAGGER,
};

#define FLAGS_RW_MASK 0x54 /* (01010100) */

#define IS_SERVICE(is)				\
			(test_bit(ISG_IS_SERVICE, &is->info.flags))

#define IS_SERVICE_ONLINE(is)			\
			(IS_SERVICE(is) &&		\
			test_bit(ISG_SERVICE_ONLINE, &is->info.flags))

#define IS_SESSION_APPROVED(is)			\
			(test_bit(ISG_IS_APPROVED, &is->info.flags))

#define IS_SESSION_DYING(is) \
			(test_bit(ISG_IS_DYING, &is->info.flags))

struct isg_session_rate {
	u32 rate;			/* Policing (rate/burst) info (kbit/s) */
	u32 burst;
};

struct isg_session_info_v0 {
	u64 id;
	u8 cookie[32];

	u32 ipaddr;			/* User's IP-address */
	u32 nat_ipaddr;			/* User's 1-to-1 NAT IP-address */
	u8 macaddr[ETH_ALEN];		/* User's MAC-address */
	u8 pad0[2];			/* Pad to 4 bytes boundary */
	unsigned long flags;		/* Must be unsigned long to proper use bit-ops */

	u32 port_number;		/* Virtual port number for session */
	u32 export_interval;		/* Session statistics export interval (in nanoseconds) */
	u32 idle_timeout;		/* Session idle timeout (in nanoseconds) */
	u32 max_duration;		/* Max session duration time (in nanoseconds) */

	struct isg_session_rate rate[2];/* Policing (rate/burst) info (kbit/s) */
};

struct isg_session_info {
	u64 id;
	u8 cookie[32];

	u32 ipaddr;			/* User's IP-address */
	u32 nat_ipaddr;			/* User's 1-to-1 NAT IP-address */
	u8 macaddr[ETH_ALEN];		/* User's MAC-address */
	u8 pad0[6];			/* Pad to 8 bytes boundary */
	u32 port_number;		/* Virtual port number for session */
	unsigned long flags;		/* Must be unsigned long to proper use bit-ops */

	u64 export_interval;		/* Session statistics export interval (in nanoseconds) */
	u64 idle_timeout;		/* Session idle timeout (in nanoseconds) */
	u64 max_duration;		/* Max session duration time (in nanoseconds) */

	struct isg_session_rate rate[2];/* Policing (rate/burst) info (kbit/s) */
};

struct isg_ev_session_stat {
	u32 duration;		/* Session duration (seconds) */
	u32 padding;		/* For in_packets field proper alignment on 64-bit systems */

	u64 in_packets;		/* Statistics for session traffic */
	u64 in_bytes;
	u64 out_packets;
	u64 out_bytes;
};

struct isg_session_stat {
	spinlock_t lock;
	u8  pad0[4];
	u64 packets;		/* Statistics for session traffic */
	u64 bytes;
	u64 tokens;
	u64 last_seen;
	u64 pad1[3];
};

struct isg_session {
	struct isg_session_stat stat[2]; /* replace with array for every direction */

	u64 start_ktime;
	u64 last_export;
	unsigned int hash_key;
	struct timer_list timer;


	struct isg_session_info info;
	spinlock_t lock;

	struct isg_session_rate __rcu *rate;
	struct isg_net *isg_net;
	struct hlist_bl_node list;		/* Main list of sessions (isg_hash) */
	struct isg_service_desc *sdesc;		/* Service description for this sub-session */
	struct isg_session *parent_is;		/* Parent session (only for sub-sessions/services) */

	struct hlist_head srv_head;		/* This session sub-sessions (services) list */
	struct hlist_node srv_node;

};

#define FLAG_OP_SET   0x01
#define FLAG_OP_UNSET 0x02

static inline
void isg_session_info_v0_fill(struct isg_session_info_v0 *out, struct isg_session_info *in)
{
	memcpy(out, in, offsetof(struct isg_session_info, pad0));
	out->flags = in->flags;
	out->port_number = in->port_number;
	out->export_interval = (u32)div_u64(in->export_interval, NSEC_PER_SEC);
	out->idle_timeout = (u32)div_u64(in->idle_timeout, NSEC_PER_SEC);
	out->max_duration = (u32)div_u64(in->max_duration, NSEC_PER_SEC);
	memcpy(out->rate, in->rate, 2 * sizeof(struct isg_session_rate));
}

static inline
void isg_session_info_v1_fill(struct isg_session_info *out, struct isg_session_info_v0 *in)
{
	memcpy(out, in, offsetof(struct isg_session_info, pad0));
	out->flags = in->flags;
	out->port_number = in->port_number;
	out->export_interval = (u64)(in->export_interval * NSEC_PER_SEC);
	out->idle_timeout = (u64)(in->idle_timeout * NSEC_PER_SEC);
	out->max_duration = (u64)(in->max_duration * NSEC_PER_SEC);
	memcpy(out->rate, in->rate, 2 * sizeof(struct isg_session_rate));
}

struct isg_in_event {
	u32 type;
	u8 pad[4];
	union {
		struct isg_session_info_in {
			struct isg_session_info_v0 sinfo;
			u8 service_name[32];
			u8 flags_op;
			u8 pad[7];
		} si;

		struct nehash_entry_in {
			u32 pfx;
			u32 mask;
			u8 tc_name[32];
		} ne;

		struct service_desc_in {
			u8 tc_name[32];
			u8 service_name[32];
			u8 flags;
			u8 pad[7];
		} sdesc;
	};
};

struct isg_out_event {
	u32 type;
	u8 pad[4];
	struct isg_session_info_v0 sinfo;
	struct isg_ev_session_stat sstat;
	u64 parent_session_id;		/* Parent session-ID (only for sub-sessions/services) */
	u8 service_name[32];		/* Service name (only for sub-sessions/services) */
};

struct isg_out_event_v1 {
	u32 type;
	u8 pad[4];
	struct isg_session_info sinfo;
	struct isg_ev_session_stat sstat;
	u64 parent_session_id;		/* Parent session-ID (only for sub-sessions/services) */
	u8 service_name[32];		/* Service name (only for sub-sessions/services) */
};

struct traffic_class {
	struct hlist_node list;
	u8 name[32];
};

struct nehash_entry {
	struct hlist_node list;
	u32 pfx;
	u32 mask;
	struct traffic_class *tc;
};

struct isg_service_desc {
	struct hlist_node list;
	u8 name[32];
	u8 flags;
#define SERVICE_DESC_IS_DYNAMIC	(1 << 0)
	struct traffic_class *tcs[MAX_SD_CLASSES];
};

struct isg_net_stat {
	int approved;
	int unapproved;
	int dying;
};

struct isg_net {
	struct hlist_bl_head *hash;

	rwlock_t nehash_rw_lock;
	struct hlist_head *nehash;
	struct hlist_head nehash_queue;
	struct hlist_head traffic_class;
	rwlock_t services_rw_lock;
	struct hlist_head services;

	struct sock *sknl;
	pid_t listener_pid;
	u8 listener_ver;

	unsigned long *port_bitmap;

	struct ctl_table_header *sysctl_hdr;

	struct isg_net_stat __percpu *cnt;

	unsigned int approve_retry_interval;
	unsigned int tg_permit_action;
	unsigned int tg_deny_action;
	unsigned int pass_outgoing;
};

extern unsigned int nehash_key_len;
extern spinlock_t isg_lock;

extern int nehash_init(struct isg_net *);
extern int nehash_add_to_queue(struct isg_net *, u32, u32, u8 *);
extern int nehash_commit_queue(struct isg_net *);
extern struct nehash_entry *nehash_lookup(struct isg_net *, u32);
extern void nehash_sweep_queue(struct isg_net *);
extern void nehash_sweep_entries(struct isg_net *);
extern void nehash_free_everything(struct isg_net *);
extern struct traffic_class *nehash_find_class(struct isg_net *, u8 *);

#endif

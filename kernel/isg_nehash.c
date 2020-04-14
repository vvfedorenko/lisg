#include <linux/inetdevice.h>

#include "isg_main.h"

int nehash_init(struct isg_net *isg_net) {
	int i;
	int nr_buckets = 1 << nehash_key_len;
	int hsize = sizeof(struct hlist_head) * nr_buckets;

	isg_net->nehash = vmalloc(hsize);
	if (isg_net->nehash == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < nr_buckets; i++) {
		INIT_HLIST_HEAD(&isg_net->nehash[i]);
	}

	INIT_HLIST_HEAD(&isg_net->nehash_queue);
	INIT_HLIST_HEAD(&isg_net->traffic_class);
	rwlock_init(&isg_net->nehash_rw_lock);
	printk(KERN_INFO "ipt_ISG: Network hash table (%ld Kbytes of %u buckets, using /%d prefixes)\n", (long) hsize / 1024, nr_buckets, nehash_key_len);

	return 0;
}

int nehash_add_to_queue(struct isg_net *isg_net, u_int32_t pfx, u_int32_t mask, u_int8_t *class_name) {
	struct nehash_entry *ne;
	struct traffic_class *tc;

	ne = kzalloc(sizeof(struct nehash_entry), GFP_ATOMIC);

	if (!ne) {
		printk(KERN_ERR "ipt_ISG: nehash_entry allocation failed\n");
		return -ENOMEM;
	}

	ne->pfx  = pfx;
	ne->mask = mask;
	ne->tc   = nehash_find_class(isg_net, class_name);

	if (ne->tc == NULL) {
		tc = kzalloc(sizeof(struct traffic_class), GFP_ATOMIC);

		if (!tc) {
			printk(KERN_ERR "ipt_ISG: isg_net->traffic_class allocation failed\n");
			return -ENOMEM;
		}

		ne->tc = tc;
		memcpy(tc->name, class_name, sizeof(tc->name));

		hlist_add_head(&tc->list, &isg_net->traffic_class);
	}

	hlist_add_head(&ne->list, &isg_net->nehash_queue);

	return 0;
}

static int nehash_insert(struct isg_net *isg_net, u_int32_t pfx, u_int32_t mask, struct traffic_class *tc) {
	u_int32_t key, first, last, idx;
	struct nehash_entry *ne, *cne = NULL, *last_ne = NULL;

	key  = ntohl(pfx);
	mask = ntohl(mask);
	key  = key & mask;

	first = key >> (32 - nehash_key_len);

	if (!mask) { /* Catch all entry */
		last = first;
	} else {
		last = (key | ~mask) >> (32 - nehash_key_len);
	}

	for (idx = first; idx <= last; idx++) {
		ne = kzalloc(sizeof(struct nehash_entry), GFP_ATOMIC);

		if (!ne) {
			printk(KERN_ERR "ipt_ISG: nehash_entry allocation failed\n");
			return -ENOMEM;
		}

		ne->pfx  = key;
		ne->mask = mask;
		ne->tc   = tc;

		if (hlist_empty(&isg_net->nehash[idx])) {
			hlist_add_head(&ne->list, &isg_net->nehash[idx]);
		} else {
			hlist_for_each_entry(cne, &isg_net->nehash[idx], list) {
				if (ne->mask > cne->mask) {
					break;
				}
				last_ne = cne;
			}

			if (last_ne) {
				#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
					hlist_add_after(&last_ne->list, &ne->list);
				#else
					hlist_add_behind(&ne->list, &last_ne->list);
				#endif
			} else {
				hlist_add_before(&ne->list, &cne->list);
			}
		}
	}
	return 0;
}

inline struct nehash_entry *nehash_lookup(struct isg_net *isg_net, u_int32_t ipaddr) {
	struct nehash_entry *ne;

	u_int32_t key, idx;

	key = ntohl(ipaddr);
	idx = key >> (32 - nehash_key_len);

	hlist_for_each_entry(ne, &isg_net->nehash[idx], list) {
		if ((key & ne->mask) == ne->pfx) {
			return ne;
		}
	}

	/* Trying to use "default" */
	hlist_for_each_entry(ne, &isg_net->nehash[0], list) {
		if (ne->pfx == 0 && ne->mask == 0) {
			return ne;
		}
	}

	return NULL;
}

struct traffic_class *nehash_find_class(struct isg_net *isg_net, u_int8_t *class_name) {
	struct traffic_class *tc;

	hlist_for_each_entry(tc, &isg_net->traffic_class, list) {
		if (!strcmp(tc->name, class_name)) {
			return tc;
		}
	}
	return NULL;
}

int nehash_commit_queue(struct isg_net *isg_net) {
	struct nehash_entry *ne;

	write_lock_bh(&isg_net->nehash_rw_lock);

	nehash_sweep_entries(isg_net);

	hlist_for_each_entry(ne, &isg_net->nehash_queue, list) {
		nehash_insert(isg_net, ne->pfx, ne->mask, ne->tc);
	}

	write_unlock_bh(&isg_net->nehash_rw_lock);

	nehash_sweep_queue(isg_net);

	return 0;
}

void nehash_sweep_queue(struct isg_net *isg_net) {
	struct nehash_entry *ne;
	struct hlist_node *n;

	hlist_for_each_entry_safe(ne, n, &isg_net->nehash_queue, list) {
		hlist_del(&ne->list);
		kfree(ne);
	}
}

static void nehash_sweep_tc(struct isg_net *isg_net) {
	struct traffic_class *tc;
	struct hlist_node *n;

	hlist_for_each_entry_safe(tc, n, &isg_net->traffic_class, list) {
		hlist_del(&tc->list);
		kfree(tc);
	}
}

void nehash_sweep_entries(struct isg_net *isg_net) {
	int i;

	struct nehash_entry *ne;
	struct hlist_node *n;

	for (i = 0; i < (1 << nehash_key_len); i++) {
		hlist_for_each_entry_safe(ne, n, &isg_net->nehash[i], list) {
			hlist_del(&ne->list);
			kfree(ne);
		}
	}
}

void nehash_free_everything(struct isg_net *isg_net) {
	nehash_sweep_queue(isg_net);

	nehash_sweep_entries(isg_net);
	nehash_sweep_tc(isg_net);

	if (isg_net->nehash) {
		vfree(isg_net->nehash);
		isg_net->nehash = NULL;
	}
}

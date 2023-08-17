#ifndef _ISG_H
#define _ISG_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
#error Minimum Kernel version is 2.6.38
#endif

#define INIT_SESSION  0x01
#define INIT_BY_SRC   0x02
#define INIT_BY_DST   0x04
#define ACTIVE_SESSION   0x02
#define INACTIVE_SESSION 0x04
#define MAX_SERVICE_NAME 32
struct ipt_ISG_info {
	unsigned char flags;
};

struct ipt_ISG_mt_info {
	char service_name[MAX_SERVICE_NAME];
	unsigned char flags;

};

#endif

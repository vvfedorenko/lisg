#ifndef _ISG_H
#define _ISG_H

#define INIT_SESSION  0x01
#define INIT_BY_SRC   0x02
#define INIT_BY_DST   0x04
#define MAX_SERVICE_NAME 32
struct ipt_ISG_info {
	u_int8_t flags;
};

struct ipt_ISG_mt_info {
	char service_name[MAX_SERVICE_NAME];
};

#endif
